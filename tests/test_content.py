from __future__ import annotations

import builtins
import contextlib
import errno
import hashlib
import io
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))

import kilix_content  # noqa: E402
from kilix_content import (  # noqa: E402
    ActionSpec,
    Catalog,
    CatalogError,
    ContentSpec,
    Installer,
    InstallError,
    LifecycleSpec,
    PackageSpec,
    default_catalog,
    download,
    safe_extract_tar,
    safe_extract_zip,
    verify_git_checkout,
)
from kilix_content import install as install_module  # noqa: E402
from kilix_content.install import (  # noqa: E402
    _rename_exchange,
    _run,
    _run_with_tail,
)


def run(*argv: str, cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def process_group(pid: int) -> int | None:
    """The process-group id of one pid, or None if it is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as stream:
            raw = stream.read(4096)
    except OSError:
        return None
    try:
        return int(raw[raw.rfind(b")") + 2:].split()[2])
    except (IndexError, ValueError):
        return None


def is_running(pid: int) -> bool:
    """Report whether one PID is live right now, without waiting for it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def outlives(pid: int, timeout: float = 5.0) -> bool:
    """Report whether a PID is still live after waiting up to ``timeout``.

    Used for assertions that a descendant is *gone*: a bare liveness check
    immediately after the call under test would pass for the wrong reason if
    the kernel had simply not scheduled the reaper yet.
    """
    deadline = time.monotonic() + timeout
    while is_running(pid):
        if time.monotonic() >= deadline:
            return True
        time.sleep(0.02)
    return False


def descendant_script(
    marker: Path, *, exit_code: int, closed_stdio: bool, lifetime: int = 60
) -> str:
    """Shell that backgrounds a same-group sleeper, then exits ``exit_code``.

    With ``closed_stdio`` the descendant drops the inherited pipe, which is the
    shape that hides it from any pipe-EOF based wait.

    ``lifetime`` is the sleeper's duration. It stays long by default so a
    descendant cannot pass a liveness assertion merely by outliving it. A
    caller may shorten it where a *mutant* would otherwise block on that
    sleeper and race the mutation harness's watchdog.
    """
    redirect = "exec </dev/null >/dev/null 2>&1; " if closed_stdio else ""
    return (
        f"sh -c 'echo $$ > \"{marker}\"; {redirect}exec sleep {lifetime}' &\n"
        f"exit {exit_code}\n"
    )


def descendant_pid(marker: Path, timeout: float = 5.0) -> int:
    """Read the PID the backgrounded descendant recorded."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = marker.read_text().strip()
        except OSError:
            text = ""
        if text:
            return int(text)
        time.sleep(0.01)
    raise AssertionError("the fixture descendant never recorded its pid")


class ContentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_packaged_catalog_is_valid_and_immutable(self) -> None:
        catalog = default_catalog()
        self.assertIs(catalog, default_catalog())
        self.assertGreaterEqual(len(catalog), 12)
        for entry in catalog:
            self.assertEqual(entry.canonicalized(), entry)
        self.assertEqual(catalog.require("kilix-jpak").launch_mode, "terminal")
        self.assertEqual(catalog.require("kilix-rancher").binary, "kilix-rancher")
        self.assertEqual(catalog.require("kilix-pong").icon, "pong")
        lights = catalog.require("kilix-lights")
        self.assertEqual(lights.binary, "bin/kilix-lights")
        self.assertIn("kitty-mouse", lights.capabilities)
        self.assertEqual(catalog.require("kilix-amp").launch_mode, "xpane")
        pdf_viewer = catalog.require("kilix-pdf")
        self.assertEqual(pdf_viewer.binary, "kilix-pdf-viewer")
        self.assertEqual(pdf_viewer.build, ("make", "all"))
        self.assertEqual(pdf_viewer.launch_mode, "terminal")
        self.assertEqual(pdf_viewer.preferred_size, "960x700")
        self.assertIn("application/pdf", pdf_viewer.accepts)
        self.assertTrue(pdf_viewer.require_action("open").accepts_input)
        pdf_conversion = catalog.require("kilix-pdf-conversion")
        self.assertEqual(pdf_conversion.binary, "kilix-pdf")
        self.assertEqual(pdf_conversion.build, ("make", "runtime"))
        self.assertEqual(pdf_conversion.launch_mode, "terminal")
        self.assertEqual(pdf_conversion.preferred_size, "760x520")
        self.assertIn("uv", pdf_conversion.dependency_hint)
        files = catalog.require("kilix-file")
        system = catalog.require("kilix-system-center")
        self.assertEqual(files.install_id, "kilix-tui-utils")
        self.assertEqual(system.install_id, "kilix-tui-utils")
        self.assertEqual(
            files.ref, "dc462372aa7417fa9bfccd82b8312d62d1077f82"
        )
        self.assertEqual(files.require_action("open").argv, ("--open",))
        self.assertIn("application/pdf", pdf_conversion.accepts)
        self.assertTrue(catalog.require("kilix-session-center").lifecycle.degrades_inplace)
        self.assertEqual(catalog.require("kilix-model-store").command,
                         ("kilix", "bonsai"))
        land = catalog.require("kilix-land")
        self.assertEqual(land.binary, "kilix-land")
        self.assertEqual(land.build, ("make", "all"))
        self.assertEqual(land.kind, "game")
        self.assertIn("kitty-graphics", land.capabilities)
        tmux_manager = catalog.require("kilix-tmux-manager")
        self.assertEqual(tmux_manager.command, ("kilix", "tmux"))
        self.assertEqual(tmux_manager.source_type, "system")
        self.assertTrue(tmux_manager.lifecycle.single_instance)
        self.assertEqual(tmux_manager.lifecycle.startup_timeout_seconds, 30)
        self.assertEqual(tmux_manager.preferred_size, "900x620")
        for entry in catalog:
            if entry.source_type == "git":
                self.assertEqual(len(entry.ref), 40)
            if entry.build[:1] == ("make",):
                expected_target = (
                    "runtime"
                    if entry.content_id == "kilix-pdf-conversion"
                    or entry.install_id == "kilix-tui-utils"
                    else "all"
                )
                self.assertEqual(entry.build, ("make", expected_target))
        with self.assertRaises(TypeError):
            catalog._by_id["replacement"] = catalog.require("kilix-jpak")

    def test_staged_entries_merge_into_the_packaged_catalog(self) -> None:
        """Finished entries staged until their pinned builds are public.

        Every entry in the packaged catalog is installable exactly as
        written, so an entry whose build only works at a commit that has
        not reached its public repository yet cannot ship there. Each
        fixture below is the exact object destined for the packaged
        catalog's content array, with its ref pinned to the entry
        repository's current public commit. Promotion advances that pin
        to the public commit that carries the entry's build and moves
        the object into plebian.json unchanged.
        """
        staged_dir = Path(__file__).resolve().parent / "staged"
        staged = {
            path.stem: json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(staged_dir.glob("*.json"))
        }
        self.assertEqual(sorted(staged), ["dosbox-kilix", "tmux-browse"])
        shipped = default_catalog()
        for content_id, entry in staged.items():
            self.assertEqual(entry["id"], content_id)
            self.assertIsNone(shipped.get(content_id))
        packaged = json.loads(
            (ROOT / "src/kilix_content/catalog/plebian.json").read_text(
                encoding="utf-8"
            )
        )
        merged = Catalog.from_mapping(
            {**packaged, "content": packaged["content"] + list(staged.values())}
        )
        self.assertEqual(len(merged), len(shipped) + len(staged))
        dosbox = merged.require("dosbox-kilix")
        self.assertEqual(
            dosbox.repository, "https://github.com/itsmygithubacct/dosbox-kilix"
        )
        self.assertEqual(len(dosbox.ref), 40)
        self.assertEqual(dosbox.binary, "src/dosbox-x")
        self.assertEqual(dosbox.build, ("make", "-j8", "all"))
        self.assertEqual(dosbox.kind, "app")
        self.assertEqual(dosbox.launch_mode, "terminal")
        self.assertIn("kitty-graphics", dosbox.capabilities)
        browse = merged.require("tmux-browse")
        self.assertEqual(
            browse.repository, "https://github.com/itsmygithubacct/tmux-browse"
        )
        self.assertEqual(len(browse.ref), 40)
        self.assertEqual(browse.binary, "bin/serve_local.sh")
        self.assertEqual(
            browse.build, ("git", "submodule", "update", "--init", "tmux-cli")
        )
        self.assertEqual(browse.kind, "app")
        self.assertEqual(browse.launch_mode, "terminal")
        self.assertTrue(browse.lifecycle.single_instance)
        self.assertIn("session-read", browse.capabilities)

    def test_runtime_and_package_versions_match(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
        self.assertIsNotNone(declared)
        self.assertEqual(kilix_content.__version__, declared.group(1))

    def test_catalog_rejects_mutable_refs_paths_and_duplicates(self) -> None:
        base = {
            "id": "fixture",
            "label": "Fixture",
            "source": {"type": "git", "repository": "fixture", "ref": "a" * 40},
            "binary": "fixture",
        }
        with self.assertRaises(CatalogError):
            ContentSpec.from_mapping(
                {**base, "source": {**base["source"], "ref": "main"}}
            )
        with self.assertRaises(CatalogError):
            ContentSpec.from_mapping({**base, "binary": "../fixture"})
        spec = ContentSpec.from_mapping(base)
        with self.assertRaises(CatalogError):
            Catalog((spec, spec))

    def test_catalog_rejects_unknown_fields_and_wrong_scalar_types(self) -> None:
        base = {
            "id": "fixture",
            "label": "Fixture",
            "source": {"type": "git", "repository": "fixture", "ref": "a" * 40},
            "binary": "fixture",
        }
        invalid_entries = (
            7,
            {**base, "unknown": "value"},
            {**base, "source": {**base["source"], "unknown": "value"}},
            {**base, "launch": {"unknown": "value"}},
            {**base, "source": {"type": []}},
            {**base, "launch": {"mode": []}},
            {**base, "binary": 0},
            {**base, "binary": "bad\x00path"},
            {**base, "launch": {"preferred_size": "wide"}},
        )
        for entry in invalid_entries:
            with self.subTest(entry=entry), self.assertRaises(CatalogError):
                ContentSpec.from_mapping(entry)
        invalid_catalogs = (
            {"schema_version": True, "content": []},
            {"schema_version": 1, "content": [], "unknown": "value"},
            {"schema_version": 1, "content": [7]},
        )
        for catalog in invalid_catalogs:
            with self.subTest(catalog=catalog), self.assertRaises(CatalogError):
                Catalog.from_mapping(catalog)

    def test_catalog_loader_rejects_duplicate_keys_and_oversize_input(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1,"content":[]}', encoding="utf-8"
        )
        with self.assertRaisesRegex(CatalogError, "duplicate"):
            Catalog.load(duplicate)
        oversized = self.root / "oversized.json"
        oversized.write_text(" " * (1024 * 1024 + 1), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "size limit"):
            Catalog.load(oversized)
        with self.assertRaisesRegex(CatalogError, "numeric limit"):
            Catalog.loads('{"schema_version":' + "9" * 5000 + ',"content":[]}')

    def test_direct_catalog_mapping_has_equivalent_semantic_budgets(self) -> None:
        base = {
            "id": "fixture",
            "label": "Fixture",
            "source": {"type": "system"},
            "command": ["fixture"],
        }
        with self.assertRaises(CatalogError):
            Catalog.from_mapping(
                {
                    "schema_version": 3,
                    "content": [{**base, "description": "x" * 900_000}],
                }
            )
        with self.assertRaises(CatalogError):
            Catalog.loads(
                json.dumps(
                    {
                        "schema_version": 3,
                        "content": [{**base, "description": "x" * 900_000}],
                    }
                )
            )
        with self.assertRaises(CatalogError):
            ContentSpec.from_mapping({**base, "description": "x" * 2_000_000})
        with self.assertRaisesRegex(CatalogError, "at most 256"):
            ContentSpec.from_mapping(
                {**base, "capabilities": ["capability"] * 100_000}
            )
        oversized_mapping = {
            "schema_version": 3,
            "content": [
                {
                    **base,
                    "id": f"fixture-{index}",
                    "description": "x" * 4096,
                }
                for index in range(300)
            ],
        }
        with self.assertRaisesRegex(CatalogError, "1 MiB"):
            Catalog.from_mapping(oversized_mapping)

        nested: object = []
        for _ in range(70):
            nested = [nested]
        with self.assertRaisesRegex(CatalogError, "nesting"):
            Catalog.from_mapping(
                {"schema_version": 3, "content": [], "assets": nested}
            )

    def test_schema_two_packages_flatten_into_shared_content_specs(self) -> None:
        source, _ref = self._git_fixture()
        second = source / "second"
        second.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        second.chmod(0o755)
        run("git", "add", "second", cwd=source)
        run("git", "commit", "--quiet", "-m", "provide second", cwd=source)
        ref = run("git", "rev-parse", "HEAD", cwd=source)
        catalog = Catalog.from_mapping(
            {
                "schema_version": 2,
                "packages": [
                    {
                        "id": "fixture-suite",
                        "source": {
                            "type": "git",
                            "repository": str(source),
                            "ref": ref,
                        },
                        "build": [
                            sys.executable,
                            "-c",
                            "print('built shared fixture package')",
                        ],
                        "dependency_hint": "needs the fixture runtime",
                    }
                ],
                "content": [
                    {
                        "id": "fixture-first",
                        "label": "Fixture First",
                        "kind": "app",
                        "package": "fixture-suite",
                        "binary": "fixture",
                    },
                    {
                        "id": "fixture-second",
                        "label": "Fixture Second",
                        "kind": "app",
                        "package": "fixture-suite",
                        "binary": "second",
                    },
                ],
            }
        )

        first = catalog.require("fixture-first")
        sibling = catalog.require("fixture-second")
        package = catalog.require_package("fixture-suite")
        self.assertEqual(catalog.packages, (package,))
        self.assertEqual(first.package_id, "fixture-suite")
        self.assertEqual(first.install_id, "fixture-suite")
        self.assertEqual(first.repository, str(source))
        self.assertEqual(first.ref, ref)
        self.assertEqual(first.build, package.build)
        self.assertEqual(first.dependency_hint, "needs the fixture runtime")
        self.assertTrue(package.supplies(first))
        self.assertEqual(first.canonicalized(), first)
        self.assertEqual(sibling.canonicalized(), sibling)
        self.assertEqual(
            catalog.provided_by("fixture-suite"), (first, sibling)
        )

        data = self.root / "shared-data"
        installer = Installer(
            str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        first_executable = installer.ensure(first)
        with mock.patch.object(
            installer,
            "_ensure_git",
            side_effect=AssertionError("shared package was installed twice"),
        ):
            sibling_executable = installer.ensure(sibling)
        self.assertEqual(first_executable, str(data / "fixture-suite/fixture"))
        self.assertEqual(sibling_executable, str(data / "fixture-suite/second"))
        self.assertEqual(installer.destination(first), installer.destination(sibling))
        with mock.patch(
            "kilix_content.install.verify_git_checkout",
            wraps=verify_git_checkout,
        ) as verify:
            readiness = installer.ready_provided(
                catalog.provided_by("fixture-suite")
            )
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(readiness["fixture-first"], first_executable)
        self.assertEqual(readiness["fixture-second"], sibling_executable)
        self.assertEqual(
            [path.name for path in data.iterdir()], ["fixture-suite"]
        )

        unrelated = ContentSpec.from_mapping(
            {
                "id": "unrelated",
                "label": "Unrelated",
                "source": {"type": "system"},
                "binary": "unrelated",
            }
        )
        with self.assertRaisesRegex(InstallError, "shared installation identity"):
            installer.ready_provided((first, unrelated))

    def test_schema_two_rejects_invalid_or_ambiguous_packages(self) -> None:
        package = {
            "id": "fixture-suite",
            "source": {
                "type": "git",
                "repository": "fixture",
                "ref": "a" * 40,
            },
        }
        entry = {
            "id": "fixture",
            "label": "Fixture",
            "kind": "app",
            "package": "fixture-suite",
            "binary": "fixture",
        }
        invalid = (
            {"schema_version": 1, "packages": [package], "content": []},
            {"schema_version": 2, "packages": {}, "content": []},
            {
                "schema_version": 2,
                "packages": [package, package],
                "content": [entry],
            },
            {
                "schema_version": 2,
                "packages": [{**package, "unknown": True}],
                "content": [entry],
            },
            {
                "schema_version": 2,
                "packages": [
                    {"id": "fixture-suite", "source": {"type": "system"}}
                ],
                "content": [entry],
            },
            {
                "schema_version": 2,
                "packages": [package],
                "content": [{**entry, "package": "missing"}],
            },
            {
                "schema_version": 2,
                "packages": [package],
                "content": [
                    {
                        **entry,
                        "source": {"type": "system"},
                    }
                ],
            },
            {
                "schema_version": 2,
                "packages": [package],
                "content": [{**entry, "build": ["make", "all"]}],
            },
            {
                "schema_version": 2,
                "packages": [package],
                "content": [],
            },
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(CatalogError):
                Catalog.from_mapping(payload)

        collision = {
            "schema_version": 2,
            "packages": [package],
            "content": [
                {
                    "id": "fixture-suite",
                    "label": "Conflicting direct entry",
                    "source": {
                        "type": "git",
                        "repository": "different",
                        "ref": "b" * 40,
                    },
                    "binary": "fixture",
                }
            ],
        }
        with self.assertRaisesRegex(CatalogError, "conflicts"):
            Catalog.from_mapping(collision)

        direct = PackageSpec.from_mapping(package)
        flattened = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "git",
                    "repository": "different",
                    "ref": "b" * 40,
                },
                "binary": "fixture",
            }
        )
        flattened = ContentSpec(
            **{
                **flattened.__dict__,
                "package_id": "fixture-suite",
            }
        )
        with self.assertRaisesRegex(CatalogError, "does not match"):
            Catalog((flattened,), 2, packages=(direct,))

    def test_schema_three_application_actions_inputs_and_lifecycle(self) -> None:
        catalog = Catalog.from_mapping(
            {
                "schema_version": 3,
                "content": [
                    {
                        "id": "system-center",
                        "label": "System Center",
                        "kind": "app",
                        "source": {"type": "system"},
                        "command": ["kilix-system-center"],
                        "capabilities": ["system-read"],
                        "actions": {
                            "memory": {
                                "argv": ["--place", "Memory"],
                                "description": "Open memory status",
                            },
                            "open": {
                                "argv": ["--open"],
                                "accepts_input": True,
                            },
                        },
                        "accepts": ["application/json", "directory"],
                        "lifecycle": {
                            "single_instance": True,
                            "requires_kilix_session": False,
                            "degrades_inplace": True,
                            "preserve_on_failure": True,
                            "startup_timeout_seconds": 15,
                        },
                    }
                ],
            }
        )
        spec = catalog.require("system-center")
        self.assertEqual(spec.command, ("kilix-system-center",))
        self.assertEqual(spec.accepts, ("application/json", "directory"))
        self.assertEqual(spec.require_action("memory").argv, ("--place", "Memory"))
        self.assertFalse(spec.require_action("memory").accepts_input)
        self.assertTrue(spec.require_action("open").accepts_input)
        self.assertEqual(
            spec.lifecycle,
            LifecycleSpec(
                single_instance=True,
                startup_timeout_seconds=15,
            ),
        )
        self.assertIsInstance(spec.actions[0], ActionSpec)
        with self.assertRaisesRegex(CatalogError, "unknown application action"):
            spec.require_action("missing")

    def test_schema_three_rejects_ambiguous_or_malformed_metadata(self) -> None:
        base = {
            "id": "fixture",
            "label": "Fixture",
            "kind": "app",
            "source": {"type": "system"},
            "command": ["fixture"],
        }
        invalid = (
            {"schema_version": 2, "content": [base]},
            {
                "schema_version": 3,
                "content": [{**base, "command": []}],
            },
            {
                "schema_version": 3,
                "content": [{**base, "binary": "fixture"}],
            },
            {
                "schema_version": 3,
                "content": [{**base, "actions": []}],
            },
            {
                "schema_version": 3,
                "content": [
                    {**base, "actions": {"open": {"accepts_input": 1}}}
                ],
            },
            {
                "schema_version": 3,
                "content": [
                    {**base, "lifecycle": {"single_instance": "yes"}}
                ],
            },
            {
                "schema_version": 3,
                "content": [
                    {**base, "lifecycle": {"startup_timeout_seconds": 3601}}
                ],
            },
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(CatalogError):
                Catalog.from_mapping(payload)

    def _git_fixture(self) -> tuple[Path, str]:
        dependency = self.root / "dependency"
        dependency.mkdir()
        (dependency / "value.txt").write_text("dependency\n")
        run("git", "init", "--quiet", cwd=dependency)
        run("git", "config", "user.name", "Fixture", cwd=dependency)
        run("git", "config", "user.email", "fixture@example.invalid", cwd=dependency)
        run("git", "add", "value.txt", cwd=dependency)
        run("git", "commit", "--quiet", "-m", "dependency", cwd=dependency)

        source = self.root / "source"
        source.mkdir()
        (source / "fixture").write_text("#!/bin/sh\nexit 0\n")
        os.chmod(source / "fixture", 0o755)
        run("git", "init", "--quiet", cwd=source)
        run("git", "config", "user.name", "Fixture", cwd=source)
        run("git", "config", "user.email", "fixture@example.invalid", cwd=source)
        run("git", "add", "fixture", cwd=source)
        subprocess.run(
            [
                "git",
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "--quiet",
                str(dependency),
                "third_party/dependency",
            ],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        )
        run("git", "commit", "--quiet", "-m", "fixture", cwd=source)
        return source, run("git", "rev-parse", "HEAD", cwd=source)

    def test_git_install_is_recursive_pinned_and_atomic(self) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        env = dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        installer = Installer(str(data), env=env)
        executable = installer.ensure(spec)
        self.assertEqual(executable, str(data / "fixture" / "fixture"))
        self.assertTrue(
            (data / "fixture" / "third_party/dependency/value.txt").is_file()
        )
        self.assertEqual(installer.ready(spec), executable)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

        run(
            "git",
            "remote",
            "set-url",
            "origin",
            str(source) + "-wrong",
            cwd=data / "fixture",
        )
        self.assertIsNone(installer.ready(spec))
        run("git", "remote", "set-url", "origin", str(source), cwd=data / "fixture")
        dependency_file = data / "fixture" / "third_party/dependency/value.txt"
        dependency_file.write_text("modified dependency\n", encoding="utf-8")
        self.assertIsNone(installer.ready(spec))
        run(
            "git",
            "checkout",
            "--",
            "value.txt",
            cwd=data / "fixture" / "third_party/dependency",
        )
        with (data / "fixture" / "fixture").open("a") as stream:
            stream.write("# modified\n")
        self.assertIsNone(installer.ready(spec))
        with self.assertRaises(InstallError):
            installer.ensure(spec)

    def test_configured_git_checkout_is_verified_but_plain_override_is_trusted(
        self,
    ) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        installed_root = self.root / "installed"
        installer = Installer(
            str(installed_root), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        selected = Path(installer.ensure(spec))
        configured = Installer(str(self.root / "different-root"))
        self.assertEqual(configured.ready(spec, str(selected.parent)), str(selected))

        run("git", "remote", "set-url", "origin", "wrong", cwd=selected.parent)
        self.assertIsNone(configured.ready(spec, str(selected.parent)))
        run("git", "remote", "set-url", "origin", str(source), cwd=selected.parent)
        run("git", "switch", "--quiet", "-c", "attached", cwd=selected.parent)
        self.assertIsNone(configured.ready(spec, str(selected.parent)))

        unmanaged = self.root / "unmanaged"
        unmanaged.mkdir()
        (unmanaged / "fixture").write_text("executable", encoding="utf-8")
        (unmanaged / "fixture").chmod(0o755)
        self.assertEqual(
            configured.ready(spec, str(unmanaged)), str(unmanaged / "fixture")
        )

    def test_git_verification_rejects_symlinked_metadata_and_ignores_redirect_env(
        self,
    ) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        installer = Installer(
            str(self.root / "data"), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        selected = Path(installer.ensure(spec)).parent
        with mock.patch.dict(os.environ, {"GIT_DIR": str(source / ".git")}):
            verify_git_checkout(str(source), ref, str(selected))

        external_git = self.root / "external-git"
        (selected / ".git").rename(external_git)
        (selected / ".git").symlink_to(external_git, target_is_directory=True)
        with self.assertRaises(InstallError):
            verify_git_checkout(str(source), ref, str(selected))

    def test_git_install_ignores_inherited_config_templates_and_exec_paths(
        self,
    ) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        sentinel = self.root / "inherited-hook-ran"
        hooks = self.root / "hooks"
        hooks.mkdir()
        hook = hooks / "post-checkout"
        hook.write_text(
            f"#!/bin/sh\n: > {shlex.quote(str(sentinel))}\n", encoding="utf-8"
        )
        hook.chmod(0o755)
        template = self.root / "template"
        (template / "hooks").mkdir(parents=True)
        (template / "hooks" / "post-checkout").symlink_to(hook)
        global_config = self.root / "global.gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {hooks}\n"
            f'[url "{self.root / "redirected"}"]\n'
            f"\tinsteadOf = {source}\n",
            encoding="utf-8",
        )
        empty_exec_path = self.root / "empty-git-exec-path"
        empty_exec_path.mkdir()
        environment = dict(
            os.environ,
            GIT_ALLOW_PROTOCOL="file:ext",
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_GLOBAL=str(global_config),
            GIT_CONFIG_KEY_0="core.hooksPath",
            GIT_CONFIG_VALUE_0=str(hooks),
            GIT_EXEC_PATH=str(empty_exec_path),
            GIT_TEMPLATE_DIR=str(template),
            SSH_ASKPASS=str(hook),
        )
        installer = Installer(str(self.root / "data"), env=environment)

        executable = installer.ensure(spec)

        self.assertTrue(os.access(executable, os.X_OK))
        self.assertFalse(sentinel.exists())

    def test_failed_git_fetch_leaves_no_selected_or_partial_tree(self) -> None:
        source, _ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "missing",
                "label": "Missing",
                "source": {"type": "git", "repository": str(source), "ref": "f" * 40},
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        installer = Installer(
            str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        with self.assertRaises(InstallError):
            installer.ensure(spec)
        self.assertFalse((data / "missing").exists())
        self.assertFalse(
            any(path.name.startswith(".missing.install-") for path in data.iterdir())
        )

    def test_clean_stale_git_checkout_updates_atomically(self) -> None:
        source, first_ref = self._git_fixture()
        first = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "git",
                    "repository": str(source),
                    "ref": first_ref,
                },
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        installer = Installer(
            str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        selected = Path(installer.ensure(first))
        (source / "fixture").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        run("git", "add", "fixture", cwd=source)
        run("git", "commit", "--quiet", "-m", "second", cwd=source)
        second_ref = run("git", "rev-parse", "HEAD", cwd=source)
        second = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "git",
                    "repository": str(source),
                    "ref": second_ref,
                },
                "binary": "fixture",
            }
        )

        self.assertEqual(installer.ensure(second), str(selected))
        self.assertIn("exit 2", selected.read_text(encoding="utf-8"))
        self.assertEqual(
            run("git", "rev-parse", "HEAD", cwd=selected.parent), second_ref
        )
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

    def test_successful_build_without_artifact_reports_build_output(self) -> None:
        spec = ContentSpec.from_mapping(
            {
                "id": "missing-output",
                "label": "Missing Output",
                "source": {"type": "system"},
                "binary": "missing-output",
                "build": [
                    sys.executable,
                    "-c",
                    "print('built only an internal archive')",
                ],
            }
        )
        installer = Installer(str(self.root / "data"))
        with self.assertRaisesRegex(InstallError, "built only an internal archive"):
            installer._build(spec, str(self.root), lambda _message: None)

    def test_interrupted_empty_git_init_is_replaced_atomically(self) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        interrupted = data / "fixture"
        interrupted.mkdir(parents=True)
        run("git", "init", "--quiet", cwd=interrupted)

        installer = Installer(
            str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        executable = installer.ensure(spec)

        self.assertEqual(executable, str(interrupted / "fixture"))
        self.assertEqual(run("git", "rev-parse", "HEAD", cwd=interrupted), ref)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

    def test_interrupted_git_init_with_untracked_file_is_preserved(self) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        interrupted = data / "fixture"
        interrupted.mkdir(parents=True)
        run("git", "init", "--quiet", cwd=interrupted)
        sentinel = interrupted / "personal.txt"
        sentinel.write_text("keep", encoding="utf-8")

        installer = Installer(
            str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        )
        with self.assertRaises(InstallError):
            installer.ensure(spec)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_installer_rejects_paths_from_direct_unvalidated_specs(self) -> None:
        installer = Installer(str(self.root / "data"))
        escaped_id = ContentSpec(
            "../escape", "Fixture", "game", "", "", "system", binary="fixture"
        )
        with self.assertRaises(InstallError):
            installer.destination(escaped_id)
        escaped_package = ContentSpec(
            "fixture", "Fixture", "game", "", "", "system",
            binary="fixture", package_id="../escape"
        )
        with self.assertRaises(InstallError):
            installer.destination(escaped_package)
        escaped_binary = ContentSpec(
            "fixture", "Fixture", "game", "", "", "system", binary="../escape"
        )
        with self.assertRaises(InstallError):
            installer.executable(escaped_binary)

    def test_replacement_uses_exchange_without_hiding_destination(self) -> None:
        data = self.root / "data"
        destination = data / "fixture"
        stage = data / ".fixture.install-test"
        destination.mkdir(parents=True)
        stage.mkdir()
        (destination / "value").write_text("old")
        (stage / "value").write_text("new")
        installer = Installer(str(data))
        observations: list[bool] = []

        def observed_exchange(first: str, second: str) -> None:
            observations.append(os.path.isdir(second))
            _rename_exchange(first, second)
            observations.append(os.path.isdir(second))

        with mock.patch(
            "kilix_content.install._rename_exchange", side_effect=observed_exchange
        ):
            installer._replace_stage(str(stage), str(destination))

        self.assertEqual(observations, [True, True])
        self.assertEqual((destination / "value").read_text(), "new")
        self.assertFalse(stage.exists())

    def test_failed_exchange_preserves_selected_destination(self) -> None:
        data = self.root / "data"
        destination = data / "fixture"
        stage = data / ".fixture.install-test"
        destination.mkdir(parents=True)
        stage.mkdir()
        (destination / "value").write_text("old")
        (stage / "value").write_text("new")
        installer = Installer(str(data))

        with (
            mock.patch(
                "kilix_content.install._rename_exchange",
                side_effect=OSError(errno.ENOSYS, "unsupported"),
            ),
            self.assertRaises(InstallError),
        ):
            installer._replace_stage(str(stage), str(destination))

        self.assertEqual((destination / "value").read_text(), "old")
        self.assertEqual((stage / "value").read_text(), "new")

    def test_archive_extractors_reject_traversal_and_links(self) -> None:
        destination = self.root / "out"
        destination.mkdir()
        payload = self.root / "bad.tar"
        with tarfile.open(payload, "w") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with tarfile.open(payload) as archive, self.assertRaises(InstallError):
            safe_extract_tar(archive, str(destination))

        zipped = self.root / "bad.zip"
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("../escape", b"x")
        with zipfile.ZipFile(zipped) as archive, self.assertRaises(InstallError):
            safe_extract_zip(archive, str(destination))
        self.assertFalse((self.root / "escape").exists())

        linked_tar = self.root / "linked.tar"
        with tarfile.open(linked_tar, "w") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            archive.addfile(info)
        with tarfile.open(linked_tar) as archive, self.assertRaises(InstallError):
            safe_extract_tar(archive, str(destination))

        linked_zip = self.root / "linked.zip"
        with zipfile.ZipFile(linked_zip, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
        with zipfile.ZipFile(linked_zip) as archive, self.assertRaises(InstallError):
            safe_extract_zip(archive, str(destination))

    def test_archive_extractors_bound_output_and_normalize_collisions(self) -> None:
        payload = self.root / "payload.tar"
        with tarfile.open(payload, "w") as archive:
            info = tarfile.TarInfo("value")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        destination = self.root / "tar-out"
        destination.mkdir()
        with (
            tarfile.open(payload) as archive,
            self.assertRaisesRegex(InstallError, "safety limit"),
        ):
            safe_extract_tar(archive, str(destination), max_bytes=0)

        conflict = self.root / "conflict.tar"
        with tarfile.open(conflict, "w") as archive:
            directory = tarfile.TarInfo("same")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            regular = tarfile.TarInfo("same")
            regular.size = 1
            archive.addfile(regular, io.BytesIO(b"x"))
        collision_out = self.root / "collision-out"
        collision_out.mkdir()
        with tarfile.open(conflict) as archive, self.assertRaises(InstallError):
            safe_extract_tar(archive, str(collision_out))

        zipped = self.root / "bounded.zip"
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("value", b"x")
        zip_out = self.root / "zip-out"
        zip_out.mkdir()
        with (
            zipfile.ZipFile(zipped) as archive,
            self.assertRaisesRegex(InstallError, "safety limit"),
        ):
            safe_extract_zip(archive, str(zip_out), max_bytes=0)

    def test_archive_installer_selects_verified_executable_without_partial_tree(
        self,
    ) -> None:
        payload = self.root / "fixture.tar"
        body = b"#!/bin/sh\nexit 0\n"
        with tarfile.open(payload, "w") as archive:
            info = tarfile.TarInfo("fixture")
            info.mode = 0o755
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "archive",
                    "urls": [payload.as_uri()],
                    "sha256": digest,
                },
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        installer = Installer(str(data))
        executable = installer.ensure(spec)
        self.assertEqual(executable, str(data / "fixture/fixture"))
        self.assertEqual(Path(executable).read_bytes(), body)
        self.assertEqual(installer.ensure(spec), executable)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

    def _archive_fixture_spec(self) -> ContentSpec:
        payload = self.root / "fixture.tar"
        body = b"#!/bin/sh\nexit 0\n"
        with tarfile.open(payload, "w") as archive:
            info = tarfile.TarInfo("fixture")
            info.mode = 0o755
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        return ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "archive",
                    "urls": [payload.as_uri()],
                    "sha256": digest,
                },
                "binary": "fixture",
            }
        )

    def test_install_lock_excludes_other_processes_and_reenters(self) -> None:
        data = self.root / "data"
        installer = Installer(str(data))
        lock_path = data / ".fixture.lock"
        probe = [
            sys.executable,
            "-c",
            (
                "import fcntl, os, sys\n"
                "descriptor = os.open(sys.argv[1], os.O_RDWR)\n"
                "try:\n"
                "    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                "except OSError:\n"
                "    raise SystemExit(3)\n"
                "raise SystemExit(0)\n"
            ),
            str(lock_path),
        ]
        with installer._install_lock("fixture"):
            with installer._install_lock("fixture"):  # re-entry must not deadlock
                held = subprocess.run(probe, check=False)
        self.assertEqual(held.returncode, 3)
        self.assertFalse(lock_path.exists())  # released locks leave no residue

    def test_ensure_adopts_content_selected_while_awaiting_the_lock(self) -> None:
        spec = self._archive_fixture_spec()
        data = self.root / "data"
        installer = Installer(str(data))
        selected = str(data / "fixture" / "fixture")
        with (
            mock.patch.object(installer, "ready", side_effect=[None, selected]),
            mock.patch.object(
                installer,
                "_ensure_archive",
                side_effect=AssertionError("rebuilt an installation another "
                                           "process already selected"),
            ),
        ):
            self.assertEqual(installer.ensure(spec), selected)

    def test_concurrent_ensures_share_one_installation(self) -> None:
        spec = self._archive_fixture_spec()
        data = self.root / "data"
        installer = Installer(str(data))
        results: list[str] = []
        failures: list[BaseException] = []

        def ensure() -> None:
            try:
                results.append(installer.ensure(spec))
            except BaseException as exc:  # noqa: BLE001 -- surfaced by the test
                failures.append(exc)

        threads = [threading.Thread(target=ensure) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(results, [str(data / "fixture" / "fixture")] * 2)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

    def test_selection_retries_as_exchange_when_the_destination_appears(self) -> None:
        data = self.root / "data"
        destination = data / "fixture"
        stage = data / ".fixture.install-test"
        destination.mkdir(parents=True)
        stage.mkdir()
        (destination / "value").write_text("old")
        (stage / "value").write_text("new")
        installer = Installer(str(data))
        real_lexists = os.path.lexists

        def racing_lexists(path: str) -> bool:
            if path == str(destination):
                return False  # the concurrent selection has not landed yet
            return real_lexists(path)

        with mock.patch(
            "kilix_content.install.os.path.lexists", side_effect=racing_lexists
        ):
            installer._replace_stage(str(stage), str(destination))
        self.assertEqual((destination / "value").read_text(), "new")
        self.assertFalse(stage.exists())

    def test_staging_failures_are_normalized_and_leave_no_residue(self) -> None:
        archive_spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "archive",
                    "urls": [(self.root / "unused.tar").as_uri()],
                    "sha256": "0" * 64,
                },
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        installer = Installer(str(data))

        exhausted = OSError(errno.ENOSPC, "No space left on device")
        with mock.patch(
            "kilix_content.install.tempfile.mkdtemp", side_effect=exhausted
        ):
            with self.assertRaisesRegex(InstallError, "staging directory"):
                installer.ensure(archive_spec)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

        real_mkdir = os.mkdir

        def failing_mkdir(path: str, *args: object, **kwargs: object) -> None:
            if os.path.basename(path) == "content":
                raise OSError(errno.ENOSPC, "No space left on device")
            real_mkdir(path, *args, **kwargs)

        with mock.patch("kilix_content.install.os.mkdir", side_effect=failing_mkdir):
            with self.assertRaises(InstallError):
                installer.ensure(archive_spec)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

        git_spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "git",
                    "repository": str(self.root / "unused-repository"),
                    "ref": "a" * 40,
                },
                "binary": "fixture",
            }
        )
        with mock.patch(
            "kilix_content.install.tempfile.mkdtemp", side_effect=exhausted
        ):
            with self.assertRaisesRegex(InstallError, "staging directory"):
                installer.ensure(git_spec)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

    def test_download_validates_checksum(self) -> None:
        source = self.root / "payload"
        source.write_bytes(b"payload")
        destination = self.root / "download"
        digest = hashlib.sha256(b"payload").hexdigest()
        download(source.as_uri(), str(destination), expected_sha256=digest)
        self.assertEqual(destination.read_bytes(), b"payload")
        destination.write_bytes(b"preserve")
        with self.assertRaises(InstallError):
            download(source.as_uri(), str(destination), expected_sha256="0" * 64)
        self.assertEqual(destination.read_bytes(), b"preserve")

    def test_download_advances_to_the_first_working_mirror(self) -> None:
        good = self.root / "payload"
        good.write_bytes(b"payload")
        digest = hashlib.sha256(b"payload").hexdigest()
        destination = self.root / "download"

        unreachable = (self.root / "absent-mirror").as_uri()
        download((unreachable, good.as_uri()), str(destination), expected_sha256=digest)
        self.assertEqual(destination.read_bytes(), b"payload")
        self.assertFalse(any(".download-" in path.name for path in self.root.iterdir()))

        destination.unlink()
        corrupt = self.root / "corrupt"
        corrupt.write_bytes(b"corrupt")
        download(
            (corrupt.as_uri(), good.as_uri()), str(destination), expected_sha256=digest
        )
        self.assertEqual(destination.read_bytes(), b"payload")
        self.assertFalse(any(".download-" in path.name for path in self.root.iterdir()))

    def test_failing_mirrors_report_the_last_error_and_leave_no_residue(self) -> None:
        first = (self.root / "first-absent").as_uri()
        last = (self.root / "last-absent").as_uri()
        destination = self.root / "download"
        secret = "token-4f1c9ae2-do-not-leak"

        class FirstMirrorError(OSError):
            pass

        class LastMirrorError(OSError):
            pass

        attempts: list[str] = []

        def failing_urlopen(request, *args, **kwargs):
            attempts.append(getattr(request, "full_url", str(request)))
            if len(attempts) == 1:
                raise FirstMirrorError(f"{first}?access={secret}")
            raise LastMirrorError(f"{last}?access={secret}")

        with mock.patch("urllib.request.urlopen", failing_urlopen):
            with self.assertRaises(InstallError) as raised:
                download((first, last), str(destination))

        message = str(raised.exception)
        # Baseline behavior: every mirror is attempted in order and the *last*
        # failure identifies the error, sanitized to its class name. The
        # superseded first mirror's class is not what gets reported.
        self.assertEqual(len(attempts), 2)
        self.assertIn("2", message)
        self.assertIn("LastMirrorError", message)
        self.assertNotIn("FirstMirrorError", message)
        # F100 redaction: no URL or query token reaches the diagnostic, and the
        # raw upstream exception is not retained anywhere in the rendered
        # chain, which a traceback would otherwise print.
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        rendered = "".join(
            traceback.format_exception(
                type(raised.exception),
                raised.exception,
                raised.exception.__traceback__,
            )
        )
        for leaked in (secret, "first-absent", "last-absent", "?access="):
            self.assertNotIn(leaked, message)
            self.assertNotIn(leaked, rendered)
        self.assertFalse(destination.exists())
        self.assertFalse(any(".download-" in path.name for path in self.root.iterdir()))

    def test_download_replaces_symlink_atomically_without_touching_target(self) -> None:
        source = self.root / "payload"
        source.write_bytes(b"payload")
        digest = hashlib.sha256(b"payload").hexdigest()
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        destination = self.root / "download"
        destination.symlink_to(victim)

        with mock.patch(
            "kilix_content.install.sha256_file",
            side_effect=AssertionError("second hash pass"),
        ):
            download(source.as_uri(), str(destination), expected_sha256=digest)
        self.assertFalse(destination.is_symlink())
        self.assertEqual(destination.read_bytes(), b"payload")
        self.assertEqual(victim.read_bytes(), b"keep")
        self.assertFalse(any(".download-" in path.name for path in self.root.iterdir()))

    def test_download_requires_a_candidate_and_build_spawn_errors_are_normalized(
        self,
    ) -> None:
        with self.assertRaises(InstallError):
            download((), str(self.root / "download"))
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "system"},
                "binary": "fixture",
                "build": ["definitely-no-such-kilix-content-command"],
                "dependency_hint": "install the fixture builder",
            }
        )
        with self.assertRaisesRegex(InstallError, "install the fixture builder"):
            Installer(str(self.root / "data"))._build(
                spec, str(self.root), lambda _message: None
            )

    def test_build_diagnostics_are_tail_bounded(self) -> None:
        writer = (
            "import os,sys\n"
            "block=b'x'*65536\n"
            "for _ in range(32): os.write(sys.stdout.fileno(),block)\n"
            "print('tail marker')\n"
            "raise SystemExit(7)\n"
        )
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "system"},
                "binary": "fixture",
                "build": [sys.executable, "-c", writer],
            }
        )
        with self.assertRaises(InstallError) as raised:
            Installer(str(self.root / "data"))._build(
                spec, str(self.root), lambda _message: None
            )
        message = str(raised.exception)
        self.assertLessEqual(len(message), 1024)
        self.assertIn("tail marker", message)

    def test_command_timeout_is_validated_and_bounds_stalled_builds(self) -> None:
        data = self.root / "data"
        for invalid in (0, -5, float("nan"), float("inf"), True, "60"):
            with self.assertRaises(InstallError):
                Installer(str(data), command_timeout=invalid)
        self.assertIsNone(Installer(str(data), command_timeout=None).command_timeout)
        self.assertEqual(Installer(str(data)).command_timeout, 3600.0)

        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "system"},
                "binary": "fixture",
                "build": [
                    sys.executable,
                    "-c",
                    "import time; print('tail marker', flush=True); time.sleep(60)",
                ],
            }
        )
        installer = Installer(str(data), command_timeout=0.5)
        started = time.monotonic()
        with self.assertRaisesRegex(InstallError, "timed out") as raised:
            installer._build(spec, str(self.root), lambda _message: None)
        self.assertLess(time.monotonic() - started, 30)
        self.assertIn("tail marker", str(raised.exception))

    def test_timeout_kills_the_whole_build_process_group(self) -> None:
        script = (
            "import subprocess, sys, time\n"
            "child = subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(120)']\n"
            ")\n"
            "print(child.pid, flush=True)\n"
            "time.sleep(120)\n"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(InstallError, "timed out") as raised:
            _run_with_tail(
                [sys.executable, "-c", script],
                cwd=str(self.root),
                env=dict(os.environ),
                timeout=2,
            )
        self.assertLess(time.monotonic() - started, 60)
        grandchild = int(str(raised.exception).rsplit(":", 1)[-1].split()[-1])
        for _ in range(100):
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail("a build child survived the timeout")

    def test_build_completes_and_ends_a_background_child_keeping_the_pipe(self) -> None:
        # This case previously asserted the opposite: that the background child
        # survived a successful build and had to be killed by the test. A
        # descendant that outlives the call crosses verification, atomic
        # selection and lock release, and can rewrite selected bytes afterwards.
        script = (
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(30)']\n"
            ")\n"
            "print(child.pid, flush=True)\n"
        )
        started = time.monotonic()
        returncode, tail = _run_with_tail(
            [sys.executable, "-c", script],
            cwd=str(self.root),
            env=dict(os.environ),
            timeout=60,
        )
        self.assertEqual(returncode, 0)
        self.assertLess(time.monotonic() - started, 15)
        self.assertFalse(
            outlives(int(tail.split()[-1])),
            "a background build child survived a successful build",
        )

    def test_child_command_ends_descendants_on_every_parent_outcome(self) -> None:
        for exit_code in (0, 3):
            for closed_stdio in (False, True):
                shape = f"exit={exit_code} closed_stdio={closed_stdio}"
                with self.subTest(shape):
                    marker = self.root / f"child-{exit_code}-{closed_stdio}.pid"
                    started = time.monotonic()
                    result = _run(
                        [
                            "sh",
                            "-c",
                            descendant_script(
                                marker,
                                exit_code=exit_code,
                                closed_stdio=closed_stdio,
                            ),
                        ],
                        cwd=str(self.root),
                        timeout=30,
                    )
                    elapsed = time.monotonic() - started
                    self.assertEqual(result.returncode, exit_code, shape)
                    # An inherited-stdio descendant must not wedge the call to
                    # its timeout either: the helper waits on the leader, not
                    # on the pipe.
                    self.assertLess(elapsed, 15, shape)
                    self.assertFalse(
                        outlives(descendant_pid(marker)),
                        f"a child-command descendant survived ({shape})",
                    )

    def test_build_command_ends_descendants_on_every_parent_outcome(self) -> None:
        for exit_code in (0, 3):
            for closed_stdio in (False, True):
                shape = f"exit={exit_code} closed_stdio={closed_stdio}"
                with self.subTest(shape):
                    marker = self.root / f"build-{exit_code}-{closed_stdio}.pid"
                    returncode, _tail = _run_with_tail(
                        [
                            "sh",
                            "-c",
                            descendant_script(
                                marker,
                                exit_code=exit_code,
                                closed_stdio=closed_stdio,
                            ),
                        ],
                        cwd=str(self.root),
                        env=dict(os.environ),
                        timeout=30,
                    )
                    self.assertEqual(returncode, exit_code, shape)
                    self.assertFalse(
                        outlives(descendant_pid(marker)),
                        f"a build-command descendant survived ({shape})",
                    )

    def test_commands_without_descendants_return_their_output_promptly(self) -> None:
        started = time.monotonic()
        result = _run(
            ["sh", "-c", "printf 'plain-output'"], cwd=str(self.root), timeout=30
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "plain-output")
        returncode, tail = _run_with_tail(
            ["sh", "-c", "printf 'tail-output'"],
            cwd=str(self.root),
            env=dict(os.environ),
            timeout=30,
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(tail, "tail-output")
        # Group cleanup must not turn ordinary commands into slow ones.
        self.assertLess(time.monotonic() - started, 15)

    def test_child_command_ends_descendants_when_the_caller_is_interrupted(self) -> None:
        marker = self.root / "interrupted.pid"

        def explode(process, *, label, on_cleaned=None):
            # Interrupt before any reap, which is the only state the real code
            # can reach: the leader is still unreaped and the descendant is
            # still live, so the handler must do the whole teardown itself.
            # on_cleaned is accepted and deliberately NOT called, so the phase
            # stays LIVE and the guard performs the full fallback.
            raise KeyboardInterrupt("caller interrupted")

        with mock.patch.object(
            install_module, "_reap_after_group_cleanup", explode
        ):
            with self.assertRaises(KeyboardInterrupt):
                _run(
                    [
                        "sh",
                        "-c",
                        descendant_script(marker, exit_code=0, closed_stdio=True),
                    ],
                    cwd=str(self.root),
                    timeout=30,
                )
        self.assertFalse(
            outlives(descendant_pid(marker)),
            "a descendant survived an interrupted child command",
        )

    def test_unprovable_group_cleanup_refuses_instead_of_returning(self) -> None:
        # A member that will not die must produce a refusal, never a result:
        # a value the caller cannot trust as final is worse than an error.
        leaders: list[subprocess.Popen[bytes]] = []

        def phantom_members(process, *, label="asset converter"):
            leaders.append(process)
            return (999999,)

        with mock.patch.object(
            install_module, "_live_process_group_members", phantom_members
        ):
            with self.assertRaisesRegex(InstallError, "left a surviving process"):
                _run(["sh", "-c", "exit 0"], cwd=str(self.root), timeout=30)
            with self.assertRaisesRegex(InstallError, "left a surviving process"):
                _run_with_tail(
                    ["sh", "-c", "exit 0"],
                    cwd=str(self.root),
                    env=dict(os.environ),
                    timeout=30,
                )
        self.assertTrue(leaders, "the refusal path never inspected a process group")
        # Refusing deliberately leaves the leader unreaped so its PID/PGID stays
        # reserved against the member the mock claims is still alive. Only this
        # test knows that member is fictional, so it reaps the fixtures itself.
        for leader in leaders:
            leader.wait()

    def _refusal_patches(self, events, leaders, failure, marker_holder):
        """Cleanup that raises ``failure``, recording attempts and reaps.

        The two helpers reach primary cleanup by different routes -- the
        timeout path through ``_force_group_end`` and the normal path through
        ``_reap_after_group_cleanup`` -- so both are patched and both record
        the same ``cleanup`` event. ``_teardown_process_group`` is reachable
        only from the guard's fallback, so it records distinctly.
        """
        real_wait = install_module.subprocess.Popen.wait
        real_release = install_module._release_readers

        def note(process, label):
            leaders.append(process)
            # The leader must still be unreaped -- its group id reserved --
            # at the moment cleanup runs.
            try:
                os.waitid(os.P_PID, process.pid,
                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
                events.append("identity-reserved")
            except ChildProcessError:
                events.append("already-reaped")
            # And the marked descendant must be live and in the leader's exact
            # process group right now, so the refusal is about a real
            # surviving member rather than an empty group.
            try:
                pid = descendant_pid(marker_holder[0], timeout=5.0)
            except AssertionError:
                pid = None
            if pid is not None and is_running(pid) and process_group(pid) == process.pid:
                events.append("descendant-live-in-group")
            events.append("cleanup")
            raise failure(f"{label} left a surviving process")

        def refusing_force(process, *, label="asset converter", on_cleaned=None):
            note(process, label)

        def refusing_reap(process, *, label="asset converter", on_cleaned=None):
            note(process, label)

        def counting_teardown(process, *, label="asset converter", **kwargs):
            events.append("fallback-teardown")
            return False

        def counting_wait(self_process, *args, **kwargs):
            events.append("reap")
            return real_wait(self_process, *args, **kwargs)

        def counting_release(*_args, **_kwargs):
            events.append("release-readers")
            return real_release(*_args, **_kwargs)

        return (
            mock.patch.object(install_module, "_force_group_end", refusing_force),
            mock.patch.object(
                install_module, "_reap_after_group_cleanup", refusing_reap),
            mock.patch.object(
                install_module, "_teardown_process_group", counting_teardown),
            mock.patch.object(
                install_module.subprocess.Popen, "wait", counting_wait),
            mock.patch.object(
                install_module, "_release_readers", counting_release),
        )

    def _assert_refusal_is_final(self, helper, shape, failure, expect_fallback):
        events: list[str] = []
        leaders: list[object] = []
        marker = self.root / f"refusal-{helper}-{shape}.pid"
        # A real, live, PID-marked descendant, so cleanup has something to fail
        # to clear rather than trivially succeeding.
        script = descendant_script(marker, exit_code=0, closed_stdio=True)
        if shape == "timeout":
            script = script.replace("exit 0\n", "sleep 60\n")
        patches = self._refusal_patches(events, leaders, failure, [marker])
        bound = 30 if shape == "normal" else 1
        started = time.monotonic()
        try:
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaises(InstallError):
                    if helper == "run":
                        _run(["sh", "-c", script], cwd=str(self.root),
                             timeout=bound)
                    else:
                        _run_with_tail(["sh", "-c", script], cwd=str(self.root),
                                       env=dict(os.environ), timeout=bound)
            # A refusal must be prompt: the point of not touching the readers
            # is that nothing blocks on a pipe a live writer still holds.
            self.assertLess(time.monotonic() - started, 20, "refusal was slow")
            self.assertIn("identity-reserved", events, f"{events}")
            self.assertIn(
                "descendant-live-in-group", events,
                f"no live marked descendant in the leader's group: {events}")
            self.assertEqual(
                events.count("cleanup"), 1,
                f"cleanup attempted {events.count('cleanup')} times: {events}")
            self.assertEqual(
                events.count("fallback-teardown"), 1 if expect_fallback else 0,
                f"unexpected fallback behaviour: {events}")
            self.assertEqual(
                events.count("release-readers"), 0,
                "readers were released while the process group was "
                f"unproven: {events}",
            )
            if not expect_fallback:
                self.assertEqual(
                    events.count("reap"), 0,
                    f"the leader was reaped after a refusal: {events}")
        finally:
            # This fixture deliberately defeated the real cleanup, so it owns
            # the group. Kill the exact recorded leader's group -- never by
            # name -- before any assertion failure can escape and strand it.
            for leader in leaders:
                try:
                    os.killpg(leader.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            try:
                pid = descendant_pid(marker, timeout=2.0)
            except AssertionError:
                pid = None
            if pid is not None and is_running(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for leader in leaders:
                try:
                    install_module.subprocess.Popen.wait(leader, timeout=5)
                except Exception:  # noqa: BLE001 - fixture teardown only
                    pass
            if pid is not None:
                self.assertFalse(outlives(pid), "fixture descendant survived")

    def test_child_command_refusal_does_not_clean_or_reap_twice(self) -> None:
        # A refusal is final. Retrying cleanup would re-signal a group we
        # already failed to clear, and reaping would release the leader pid we
        # deliberately hold to keep that group id reserved.
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                self._assert_refusal_is_final(
                    "run", shape, install_module._CleanupRefusal,
                    expect_fallback=False)
        # Positive control: the safety rule is ordering, not removal.  Once a
        # normal command's group is proven gone, its readers are released
        # exactly once.
        with mock.patch.object(
            install_module,
            "_release_readers",
            wraps=install_module._release_readers,
        ) as release_readers:
            completed = _run(
                ["sh", "-c", "printf ready"],
                cwd=str(self.root),
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "ready")
        self.assertEqual(release_readers.call_count, 1)

    def test_build_command_refusal_does_not_clean_or_reap_twice(self) -> None:
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                self._assert_refusal_is_final(
                    "tail", shape, install_module._CleanupRefusal,
                    expect_fallback=False)

    def _assert_cleaned_unreaped_retries_reap_only(self, helper, shape) -> None:
        """The group is proven empty, then the first reap fails.

        The guard must retry the reap ONLY. Repeating group cleanup there
        would be wrong work on an already-dead group, and a boolean
        reaped/refused pair cannot express this window at all.
        """
        events: list[str] = []
        real_wait = install_module.subprocess.Popen.wait
        real_terminate = install_module._terminate_remaining_process_group
        real_teardown = install_module._teardown_process_group
        waits = {"n": 0}

        def counting_terminate(process, *, label="asset converter"):
            events.append("group-cleanup")
            return real_terminate(process, label=label)

        def counting_teardown(process, *, label="asset converter", **kwargs):
            events.append("group-cleanup")
            return real_teardown(process, label=label, **kwargs)

        def flaky_wait(self_process, *args, **kwargs):
            waits["n"] += 1
            events.append("reap")
            if waits["n"] == 1:
                raise OSError("simulated first reap failure")
            return real_wait(self_process, *args, **kwargs)

        argv = ["sh", "-c", "exit 0" if shape == "normal" else "sleep 60"]
        bound = 30 if shape == "normal" else 1
        with mock.patch.object(
            install_module, "_terminate_remaining_process_group",
            counting_terminate
        ), mock.patch.object(
            install_module, "_teardown_process_group", counting_teardown
        ), mock.patch.object(
            install_module.subprocess.Popen, "wait", flaky_wait
        ):
            with self.assertRaises(OSError):
                if helper == "run":
                    _run(argv, cwd=str(self.root), timeout=bound)
                else:
                    _run_with_tail(argv, cwd=str(self.root),
                                   env=dict(os.environ), timeout=bound)
        self.assertEqual(
            events.count("group-cleanup"), 1,
            f"group cleanup repeated after the group was proven empty: {events}")
        self.assertEqual(
            events.count("reap"), 2,
            f"the outstanding reap was not retried exactly once: {events}")

    def test_child_command_retries_only_the_reap_after_cleanup(self) -> None:
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                self._assert_cleaned_unreaped_retries_reap_only("run", shape)

    def test_build_command_retries_only_the_reap_after_cleanup(self) -> None:
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                self._assert_cleaned_unreaped_retries_reap_only("tail", shape)

    def test_an_unrelated_cleanup_error_still_gets_fallback_cleanup(self) -> None:
        # Only a deliberate refusal is final. An unexpected failure *during*
        # cleanup means cleanup did not complete, so the guard's fallback must
        # still run -- a broad `except InstallError` would wrongly skip it.
        for helper in ("run", "tail"):
            with self.subTest(helper):
                self._assert_refusal_is_final(
                    helper, "normal", InstallError, expect_fallback=True)

    def test_unreadable_member_stat_refuses_instead_of_proving_empty(self) -> None:
        # A same-group member whose /proc stat cannot be read or parsed has an
        # UNKNOWN identity. Skipping it would falsely prove the group empty,
        # reap the leader and return a result that is not final.
        shapes = (
            ("permission", PermissionError(13, "Permission denied")),
            ("truncated", b"1234 (sh) S 1"),
            ("no-delimiter", b"1234 sh S 1 2 3 4 5"),
            # A ')' exists but is not followed by the exact ") " separator, so
            # every later field is shifted by one and a naive parse would read
            # the wrong column as the process group.
            ("bad-delimiter", b"1234 (sh)X S 1 2 3 4 5 6 7"),
        )
        for name, failure in shapes:
            with self.subTest(name):
                marker = self.root / f"unreadable-{name}.pid"
                script = descendant_script(
                    marker, exit_code=0, closed_stdio=True)
                real_open = builtins.open
                real_popen = install_module.subprocess.Popen
                leaders: list[object] = []
                witness = {"member": None, "group_ok": False}

                def recording_popen(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    leaders.append(process)
                    return process

                def hostile_open(path, *args, **kwargs):
                    text = str(path)
                    if text.startswith("/proc/") and text.endswith("/stat"):
                        pid = int(text.split("/")[2])
                        if witness["member"] is None and leaders and marker.exists():
                            try:
                                witness["member"] = descendant_pid(
                                    marker, timeout=1.0)
                            except AssertionError:
                                witness["member"] = None
                        if witness["member"] is not None and pid == witness["member"]:
                            # Evaluated at the injection point, not when the
                            # pid was first learned: the target must be a LIVE
                            # member of the exact leader group right now, or
                            # this test would prove nothing.
                            # Read the group through real_open: the module
                            # helper would re-enter this hook and recurse.
                            group = None
                            try:
                                with real_open(f"/proc/{pid}/stat", "rb") as s:
                                    blob = s.read(4096)
                                group = int(
                                    blob[blob.rfind(b")") + 2:].split()[2])
                            except (OSError, IndexError, ValueError):
                                group = None
                            witness["group_ok"] = (
                                is_running(pid) and group == leaders[0].pid)
                            if isinstance(failure, BaseException):
                                raise failure
                            return io.BytesIO(failure)
                    return real_open(path, *args, **kwargs)

                try:
                    with mock.patch.object(
                        install_module.subprocess, "Popen", recording_popen
                    ), mock.patch("builtins.open", hostile_open):
                        with self.assertRaisesRegex(
                            InstallError, "process group could not be inspected"
                        ) as raised:
                            _run(["sh", "-c", script], cwd=str(self.root),
                                 timeout=30)
                    # Unpatched from here.
                    message = str(raised.exception)
                    self.assertIn("could not be inspected", message)
                    for leaked in ("/proc", "denied", "Permission",
                                   str(self.root), str(witness["member"])):
                        self.assertNotIn(leaked, message)
                    self.assertEqual(len(leaders), 1)
                    self.assertIsNotNone(
                        witness["member"], "fixture never spawned")
                    self.assertTrue(
                        witness["group_ok"],
                        "injection target was not a live member of the leader "
                        "group; the test would be vacuous")
                    # The leader must NOT have been reaped: its identity stays
                    # reserved because the group was never proven empty.
                    try:
                        os.waitid(os.P_PID, leaders[0].pid,
                                  os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        reserved = True
                    except ChildProcessError:
                        reserved = False
                    self.assertTrue(
                        reserved, "the leader was reaped despite a refusal")
                finally:
                    # Exact, test-owned cleanup, reached even if an assertion
                    # above fails, so this fixture can never strand a sleeper.
                    for leader in leaders:
                        try:
                            os.killpg(leader.pid, signal.SIGKILL)
                        except (OSError, ProcessLookupError):
                            pass
                        try:
                            leader.wait(timeout=5)
                        except Exception:  # noqa: BLE001 - teardown only
                            pass
                    if witness["member"] and witness["member"] > 0:
                        self.assertFalse(outlives(witness["member"]))

    def _converter(self, argv, timeout=30):
        return install_module._run_converter(
            argv, cwd=str(self.root), env=dict(os.environ), timeout=timeout)

    def _converter_witness(self, marker, leaders, events):
        """Record that a marked descendant is live in the leader's exact group."""
        def note(process):
            leaders.append(process)
            try:
                os.waitid(os.P_PID, process.pid,
                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
                events.append("identity-reserved")
            except ChildProcessError:
                events.append("already-reaped")
            pid = descendant_pid(marker, timeout=10.0)
            if is_running(pid) and process_group(pid) == process.pid:
                events.append("descendant-live-in-group")
        return note

    def _kill_recorded(self, leaders, marker):
        real_wait = install_module.subprocess.Popen.wait
        for leader in leaders:
            try:
                os.killpg(leader.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                real_wait(leader, timeout=5)
            except Exception:  # noqa: BLE001 - teardown only
                pass
            # Only now, with every writer proven gone, is closing safe -- and
            # it keeps the suite free of ResourceWarnings.
            for name in ("stdout", "stderr"):
                stream = getattr(leader, name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
        try:
            pid = descendant_pid(marker, timeout=2.0)
        except AssertionError:
            return None
        return pid

    def test_converter_refusal_does_not_clean_or_reap_twice(self) -> None:
        # Same refusal contract as the other two runners, proven against a
        # real live descendant in the leader's exact group.
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                events: list[str] = []
                leaders: list[object] = []
                marker = self.root / f"conv-refusal-{shape}.pid"
                script = descendant_script(marker, exit_code=0, closed_stdio=True)
                if shape == "timeout":
                    script = script.replace("exit 0\n", "sleep 60\n")
                real_wait = install_module.subprocess.Popen.wait
                note = self._converter_witness(marker, leaders, events)

                def refusing(process, *, label="asset converter", on_cleaned=None):
                    note(process)
                    events.append("cleanup")
                    raise install_module._CleanupRefusal(
                        f"{label} left a surviving process")

                def counting_teardown(process, *, label="asset converter", **kw):
                    events.append("fallback-teardown")
                    return False

                def counting_wait(self_process, *args, **kwargs):
                    events.append("reap")
                    return real_wait(self_process, *args, **kwargs)

                started = time.monotonic()
                try:
                    with mock.patch.object(
                        install_module, "_force_group_end", refusing
                    ), mock.patch.object(
                        install_module, "_reap_after_group_cleanup", refusing
                    ), mock.patch.object(
                        install_module, "_teardown_process_group", counting_teardown
                    ), mock.patch.object(
                        install_module.subprocess.Popen, "wait", counting_wait
                    ):
                        with self.assertRaisesRegex(
                            InstallError, "left a surviving process"
                        ):
                            self._converter(["sh", "-c", script],
                                            timeout=30 if shape == "normal" else 1)
                    self.assertLess(time.monotonic() - started, 20)
                    self.assertIn("identity-reserved", events, f"{events}")
                    self.assertIn("descendant-live-in-group", events, f"{events}")
                    self.assertEqual(events.count("cleanup"), 1, f"{events}")
                    self.assertEqual(events.count("fallback-teardown"), 0, f"{events}")
                    self.assertEqual(events.count("reap"), 0, f"{events}")
                finally:
                    pid = self._kill_recorded(leaders, marker)
                    self.assertIsNotNone(pid, "fixture descendant never spawned")
                    self.assertFalse(outlives(pid))

    def test_converter_retries_only_the_reap_after_cleanup(self) -> None:
        # Both converter paths: normal reaches _reap_after_group_cleanup,
        # timeout reaches _force_group_end/_teardown_process_group.
        for shape in ("normal", "timeout"):
            with self.subTest(shape):
                events: list[str] = []
                real_wait = install_module.subprocess.Popen.wait
                real_terminate = install_module._terminate_remaining_process_group
                real_teardown = install_module._teardown_process_group
                waits = {"n": 0}

                def counting_terminate(process, *, label="asset converter"):
                    events.append("group-cleanup")
                    return real_terminate(process, label=label)

                def counting_teardown(process, *, label="asset converter", **kw):
                    events.append("group-cleanup")
                    return real_teardown(process, label=label, **kw)

                def flaky_wait(self_process, *args, **kwargs):
                    waits["n"] += 1
                    events.append("reap")
                    if waits["n"] == 1:
                        raise OSError("simulated first reap failure")
                    return real_wait(self_process, *args, **kwargs)

                argv = ["sh", "-c",
                        "exit 0" if shape == "normal" else "sleep 60"]
                with mock.patch.object(
                    install_module, "_terminate_remaining_process_group",
                    counting_terminate
                ), mock.patch.object(
                    install_module, "_teardown_process_group", counting_teardown
                ), mock.patch.object(
                    install_module.subprocess.Popen, "wait", flaky_wait
                ):
                    with self.assertRaises((OSError, InstallError)):
                        self._converter(argv, timeout=30 if shape == "normal" else 1)
                self.assertEqual(events.count("group-cleanup"), 1, f"{events}")
                self.assertEqual(events.count("reap"), 2, f"{events}")

    def test_converter_unrelated_cleanup_error_gets_fallback(self) -> None:
        # An unrelated failure during cleanup is NOT a refusal: the fallback
        # must run, really tear the group down, and preserve the sentinel.
        events: list[str] = []
        leaders: list[object] = []
        marker = self.root / "conv-unrelated.pid"
        sentinel = InstallError("asset converter process group could not be inspected")
        real_teardown = install_module._teardown_process_group
        note = self._converter_witness(marker, leaders, events)

        def unrelated(process, *, label="asset converter", on_cleaned=None):
            note(process)
            events.append("cleanup")
            raise sentinel

        def counting_teardown(process, *, label="asset converter", **kw):
            events.append("fallback-teardown")
            return real_teardown(process, label=label, **kw)

        try:
            with mock.patch.object(
                install_module, "_reap_after_group_cleanup", unrelated
            ), mock.patch.object(
                install_module, "_teardown_process_group", counting_teardown
            ):
                with self.assertRaises(InstallError) as raised:
                    self._converter([
                        "sh", "-c",
                        descendant_script(marker, exit_code=0, closed_stdio=True)])
            self.assertIs(raised.exception, sentinel, "sentinel was not preserved")
            self.assertIn("descendant-live-in-group", events, f"{events}")
            self.assertEqual(events.count("cleanup"), 1, f"{events}")
            self.assertEqual(events.count("fallback-teardown"), 1, f"{events}")
            # The fallback must have REALLY torn the group down. Asserting this
            # before the test-owned cleanup runs is what stops a no-op fallback
            # from being masked by the test's own kill.
            self.assertTrue(leaders, "no leader was recorded")
            witness_pid = descendant_pid(marker, timeout=5.0)
            self.assertFalse(
                outlives(witness_pid),
                "the fallback did not end the descendant")
            self.assertEqual(
                install_module._live_process_group_members(
                    leaders[0], label="asset converter"),
                (),
                "the fallback left group members alive")
            self.assertFalse(
                is_running(leaders[0].pid), "the leader was not reaped")
        finally:
            pid = self._kill_recorded(leaders, marker)
            self.assertIsNotNone(pid, "fixture descendant never spawned")
            self.assertFalse(outlives(pid))

    def test_converter_reader_start_failure_ends_the_group(self) -> None:
        marker = self.root / "conv-reader.pid"
        boom = RuntimeError("simulated converter reader start failure")
        real_thread = threading.Thread
        real_popen = install_module.subprocess.Popen
        leaders: list[object] = []
        observed = {}

        class FlakyThread(real_thread):
            def start(self):
                pid = descendant_pid(marker, timeout=10.0)
                observed["pid"] = pid
                observed["in_group"] = (
                    is_running(pid) and leaders
                    and process_group(pid) == leaders[0].pid)
                raise boom

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            leaders.append(process)
            return process

        try:
            with mock.patch.object(
                install_module.threading, "Thread", FlakyThread
            ), mock.patch.object(
                install_module.subprocess, "Popen", recording_popen
            ):
                with self.assertRaises(RuntimeError) as raised:
                    self._converter([
                        "sh", "-c",
                        descendant_script(marker, exit_code=0, closed_stdio=True)])
            self.assertIs(raised.exception, boom)
            self.assertIn("pid", observed)
            self.assertTrue(observed.get("in_group"), "witness was not in the group")
            self.assertFalse(outlives(observed["pid"]))
            self.assertFalse(outlives(leaders[0].pid))
        finally:
            self._kill_recorded(leaders, marker)

    def test_converter_reader_capture_failure_refuses(self) -> None:
        # reader_errors must be load-bearing: a real mid-stream read failure
        # in the converter's own reader must refuse, not truncate.
        class FailingStream:
            def __init__(self, wrapped):
                self._wrapped = wrapped
                self._calls = 0

            def read(self, size):
                self._calls += 1
                block = self._wrapped.read(size)
                if self._calls == 1 and block:
                    raise OSError("simulated converter capture failure")
                return block

            def close(self):
                return self._wrapped.close()

        real_popen = install_module.subprocess.Popen

        def wrapping_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            if process.stdout is not None:
                process.stdout = FailingStream(process.stdout)
            return process

        spawned: list[object] = []
        real_wrapping = wrapping_popen

        def recording_popen(*args, **kwargs):
            process = real_wrapping(*args, **kwargs)
            spawned.append(process)
            return process

        try:
            with mock.patch.object(
                install_module.subprocess, "Popen", recording_popen
            ):
                with self.assertRaisesRegex(
                    InstallError, "output could not be captured"
                ):
                    self._converter(["sh", "-c", "printf 'some-output'"])
        finally:
            for process in spawned:
                try:
                    process.wait(timeout=5)
                except Exception:  # noqa: BLE001 - teardown only
                    pass
                stream = getattr(process, "stdout", None)
                wrapped = getattr(stream, "_wrapped", stream)
                if wrapped is not None:
                    try:
                        wrapped.close()
                    except (OSError, ValueError):
                        pass

    def test_converter_never_closes_a_stream_a_live_reader_owns(self) -> None:
        # Deterministic and hang-free: the reader is a stub whose is_alive()
        # stays True, so the live-reader branch is genuinely exercised. A
        # stream that records close() proves production joins and returns
        # WITHOUT closing, and still refuses the capture.
        closes: list[str] = []
        real_popen = install_module.subprocess.Popen
        real_thread = install_module.threading.Thread

        class ObservingStream:
            def __init__(self, wrapped):
                self._wrapped = wrapped

            def read(self, size):
                return self._wrapped.read(size)

            def close(self):
                closes.append("closed")
                return self._wrapped.close()

        class StalledReader:
            """Never runs, never dies: is_alive() is always True."""

            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                return None

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return True

        spawned: list[object] = []

        def wrapping_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            if process.stdout is not None:
                process.stdout = ObservingStream(process.stdout)
            return process

        try:
            with mock.patch.object(
                install_module.subprocess, "Popen", wrapping_popen
            ), mock.patch.object(
                install_module.threading, "Thread", StalledReader
            ):
                with self.assertRaisesRegex(
                    InstallError, "output could not be captured"
                ):
                    self._converter(["sh", "-c", "printf 'x'"])
            self.assertEqual(
                closes, [],
                "a stream owned by a live reader was closed")
        finally:
            install_module.threading.Thread = real_thread
            # Production deliberately left this stream open -- that is the
            # property under test -- so the test owns closing it, once the
            # writer is provably gone.
            for process in spawned:
                try:
                    process.wait(timeout=5)
                except Exception:  # noqa: BLE001 - teardown only
                    pass
                stream = getattr(process, "stdout", None)
                wrapped = getattr(stream, "_wrapped", stream)
                if wrapped is not None:
                    try:
                        wrapped.close()
                    except (OSError, ValueError):
                        pass

    def test_every_child_spawn_is_lexically_inside_its_cleanup_guard(self) -> None:
        # Structural, not behavioural: an async KeyboardInterrupt between a
        # spawn and the guard that owns it would abandon a live session, and no
        # runtime test can reliably hit that window. This proves the window
        # does not exist in the source.
        import ast

        source = Path(install_module.__file__).read_text()
        tree = ast.parse(source)
        checked = []
        for function in ast.walk(tree):
            if not isinstance(function, ast.FunctionDef):
                continue
            # All three runners, not two: the converter carries the same
            # ownership contract rather than a third parallel protocol.
            if function.name not in ("_run", "_run_with_tail", "_run_converter"):
                continue
            spawns = [
                node for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "Popen"
            ]
            self.assertEqual(
                len(spawns), 1, f"{function.name}: {len(spawns)} Popen calls")
            spawn = spawns[0]
            guarded = False
            for block in ast.walk(function):
                if not isinstance(block, ast.Try) or not block.handlers:
                    continue
                # The handler must own teardown, not merely re-raise.
                handler_calls = {
                    n.func.id for h in block.handlers for n in ast.walk(h)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                }
                # Ownership means the handler actually tears down and reaps.
                # A bare signal is not sufficient evidence of ownership.
                if not {"_teardown_process_group", "_reap_only"} <= handler_calls:
                    continue
                if any(spawn is node for stmt in block.body
                       for node in ast.walk(stmt)):
                    guarded = True
                    break
            self.assertTrue(
                guarded,
                f"{function.name}: Popen is not lexically inside a cleanup Try "
                f"whose handler performs teardown")
            checked.append(function.name)
        self.assertEqual(
            sorted(checked),
            ["_run", "_run_converter", "_run_with_tail"])

    def test_the_leader_is_not_reaped_before_its_group_is_cleared(self) -> None:
        # Reaping the leader first frees its PID, so the kernel may hand that
        # id -- and therefore that process-group id -- to something unrelated
        # before the group signals are sent. The leader must still be an
        # unreaped zombie when cleanup runs.
        observed: list[str] = []
        witnessed: list[int] = []
        real_cleanup = install_module._terminate_remaining_process_group
        current = {"marker": None}

        def checking_cleanup(process, *, label="asset converter"):
            try:
                os.waitid(
                    os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                )
                observed.append("identity-reserved")
            except ChildProcessError:
                observed.append("already-reaped")
            # A live, marked member must be present, or this proves nothing.
            pid = descendant_pid(current["marker"])
            members = install_module._live_process_group_members(
                process, label=label
            )
            self.assertIn(
                pid, members, "the marked descendant was not in the exact group"
            )
            witnessed.append(pid)
            return real_cleanup(process, label=label)

        for helper in ("run", "tail"):
            marker = self.root / f"identity-{helper}.pid"
            current["marker"] = marker
            script = descendant_script(marker, exit_code=0, closed_stdio=True)
            with mock.patch.object(
                install_module,
                "_terminate_remaining_process_group",
                checking_cleanup,
            ):
                if helper == "run":
                    _run(["sh", "-c", script], cwd=str(self.root), timeout=30)
                else:
                    _run_with_tail(
                        ["sh", "-c", script],
                        cwd=str(self.root),
                        env=dict(os.environ),
                        timeout=30,
                    )
            self.assertFalse(
                outlives(descendant_pid(marker)),
                f"the {helper} descendant survived cleanup",
            )
        self.assertEqual(observed, ["identity-reserved", "identity-reserved"])
        self.assertEqual(len(witnessed), 2)

    def test_incomplete_output_capture_refuses_rather_than_truncating(self) -> None:
        # If a descendant still holds the pipe, the captured bytes are only a
        # prefix of what the command produced. Handing that back as a normal
        # CompletedProcess would let a caller act on a silently truncated
        # result, so the helper refuses instead.
        marker = self.root / "holder.pid"
        # This fixture deliberately defeats group cleanup, so the descendant
        # holds the pipe. Under the M-H mutation the helper does not refuse,
        # and _release_readers then blocks on the reader's stream lock until
        # this sleeper exits -- so an over-long lifetime would make a correct
        # M-H catch race the mutation harness's watchdog. Eight seconds keeps a
        # mutant well inside that watchdog. No elapsed bound is asserted here;
        # see the note below the call.
        script = descendant_script(
            marker, exit_code=0, closed_stdio=False, lifetime=8)
        with mock.patch.object(
            install_module,
            "_terminate_remaining_process_group",
            lambda *a, **k: None,
        ):
            with self.assertRaisesRegex(
                InstallError, "output could not be captured"
            ):
                _run(["sh", "-c", script], cwd=str(self.root), timeout=30)
        # No elapsed bound is asserted here. The no-op cleanup mock makes the
        # REAPED phase reachable while a group member is still alive -- a state
        # the real code cannot produce -- so _release_readers legitimately
        # waits out this fixture's sleeper. Bounding that would be testing the
        # mock, not the helper. The lifetime is short purely so a mutant stays
        # well inside the mutation harness's watchdog.
        # Fixture cleanup only. This test deliberately suppresses group
        # teardown, so it owns the leaked child -- but that child may already
        # have gone by the time we get here, so the kill must be idempotent.
        # The assertion that follows is the real invariant either way.
        pid = descendant_pid(marker)
        if is_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.assertFalse(outlives(pid))

    def test_group_teardown_tries_sigterm_before_sigkill(self) -> None:
        # A member that ignores SIGTERM must still die, and the SIGTERM must
        # actually have been delivered first rather than skipped for SIGKILL.
        termed = self.root / "termed"
        marker = self.root / "signal-order.pid"
        script = (
            f"sh -c 'trap \"echo termed > {termed}\" TERM; "
            f'echo $$ > "{marker}"; '
            "while :; do sleep 0.05; done' &\n"
            "while :; do sleep 0.05; done\n"
        )
        signals: list[tuple[int, float]] = []
        real_signal = install_module._signal_process_group

        def recording_signal(process, signum):
            signals.append((signum, time.monotonic()))
            return real_signal(process, signum)

        started = time.monotonic()
        with mock.patch.object(
            install_module, "_signal_process_group", recording_signal
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                _run(["sh", "-c", script], cwd=str(self.root), timeout=1)
        self.assertLess(time.monotonic() - started, 30)
        pid = descendant_pid(marker)
        self.assertFalse(
            outlives(pid), "a TERM-ignoring group member survived teardown"
        )
        self.assertTrue(
            termed.exists(),
            "teardown escalated to SIGKILL without first sending SIGTERM",
        )

        # Exact escalation order, and a real grace interval between them: a
        # TERM immediately followed by KILL gives nothing a chance to exit
        # cleanly, which is what the bounded grace exists to provide.
        order = [signum for signum, _when in signals]
        self.assertIn(signal.SIGTERM, order)
        self.assertIn(signal.SIGKILL, order)
        first_term = next(when for num, when in signals if num == signal.SIGTERM)
        first_kill = next(
            when for num, when in signals
            if num == signal.SIGKILL and when >= first_term
        )
        self.assertLess(
            order.index(signal.SIGTERM),
            order.index(signal.SIGKILL),
            "SIGKILL was sent before SIGTERM",
        )
        # The floor is a test-policy literal, deliberately NOT derived from
        # install_module._CONVERTER_TERMINATE_GRACE_SECONDS: reading the
        # constant would let a mutation that zeroes it satisfy its own
        # threshold. Production grace is 2.0s; require at least 1.0s of real
        # interval, and keep an upper bound so the escalation stays bounded.
        interval = first_kill - first_term
        self.assertGreaterEqual(
            interval,
            1.0,
            "SIGKILL followed SIGTERM without a real grace interval",
        )
        self.assertLessEqual(interval, 8.0, "the TERM grace was not bounded")
        self.assertEqual(
            install_module._CONVERTER_TERMINATE_GRACE_SECONDS,
            2.0,
            "the production grace constant moved; revisit the policy floor",
        )

    def test_build_command_ends_the_group_when_its_capture_loop_fails(self) -> None:
        # Finding D: the selector/read loop must be inside the cleanup guard.
        # A failure there previously escaped with the leader and its
        # descendants still running.
        marker = self.root / "tail-loop-failure.pid"
        boom = RuntimeError("simulated capture-loop failure")
        real_wait = install_module._wait_without_reaping
        calls = {"n": 0}

        def failing_wait(process, timeout, *, label="asset converter"):
            if label == install_module._BUILD_COMMAND_LABEL and timeout == 0:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise boom
            return real_wait(process, timeout, label=label)

        with mock.patch.object(
            install_module, "_wait_without_reaping", failing_wait
        ):
            with self.assertRaises(RuntimeError) as raised:
                _run_with_tail(
                    [
                        "sh",
                        "-c",
                        f"sh -c 'echo $$ > \"{marker}\"; exec sleep 60' &\n"
                        "sleep 60\n",
                    ],
                    cwd=str(self.root),
                    env=dict(os.environ),
                    timeout=30,
                )
        # Cleanup succeeded, so the caller sees the original failure shape.
        self.assertIs(raised.exception, boom)
        self.assertFalse(
            outlives(descendant_pid(marker)),
            "a descendant survived a failing build capture loop",
        )

    def test_build_command_ends_the_group_when_an_actual_read_fails(self) -> None:
        # Finding D, on the real capture path: the failure comes out of the
        # genuine os.read used by absorb(), after a real byte has already been
        # captured, with a marked descendant live.
        marker = self.root / "read-failure.pid"
        boom = OSError("simulated capture read failure")
        real_read = install_module.os.read
        reads = {"n": 0}

        captured: list[int] = []

        def failing_read(descriptor, size):
            block = real_read(descriptor, size)
            if block:
                captured.append(len(block))
            # Fail only after a real, NON-EMPTY block has been captured and the
            # marked descendant is actually running. Injecting after an empty
            # read would mean the real capture path had already reached EOF, so
            # the test would prove nothing about a failure mid-stream.
            reads["n"] += 1
            # The *current* block must be non-empty: injecting on an empty
            # read means this read had already reached EOF, so it would prove
            # nothing about a failure mid-stream even if an earlier block was
            # non-empty.
            if block and reads["n"] >= 2 and marker.exists():
                raise boom
            return block

        script = (
            f"sh -c 'echo $$ > \"{marker}\"; exec sleep 60' &\n"
            "while :; do echo tick; sleep 0.05; done\n"
        )
        with mock.patch.object(install_module.os, "read", failing_read):
            with self.assertRaises(OSError) as raised:
                _run_with_tail(
                    ["sh", "-c", script],
                    cwd=str(self.root),
                    env=dict(os.environ),
                    timeout=60,
                )
        # The original failure shape survives cleanup unchanged.
        self.assertIs(raised.exception, boom)
        self.assertGreaterEqual(reads["n"], 2, "the real read path was not used")
        self.assertTrue(
            captured, "no non-empty block was ever captured before injecting"
        )
        self.assertGreater(
            captured[0], 0, "the injection point saw only empty reads"
        )
        self.assertFalse(
            outlives(descendant_pid(marker)),
            "a descendant survived a real capture read failure",
        )

    def test_child_command_ends_the_group_when_reader_startup_fails(self) -> None:
        # Finding E: thread construction/start sits after Popen, so a failure
        # there must not abandon a live group. The first reader starts, the
        # second fails.
        marker = self.root / "reader-startup.pid"
        boom = RuntimeError("simulated reader thread start failure")
        real_thread = threading.Thread
        real_popen = install_module.subprocess.Popen
        made = {"n": 0}
        leaders: list[object] = []

        observed: dict[str, int] = {}

        class FlakyThread(real_thread):
            def start(self):
                made["n"] += 1
                if made["n"] == 2:
                    # Fail only once the fixture descendant is genuinely
                    # running, so this proves group cleanup rather than
                    # passing because nothing had spawned yet.
                    observed["pid"] = descendant_pid(marker, timeout=10.0)
                    raise boom
                return super().start()

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            leaders.append(process)
            return process

        with mock.patch.object(
            install_module.threading, "Thread", FlakyThread
        ), mock.patch.object(
            install_module.subprocess, "Popen", recording_popen
        ):
            with self.assertRaises(RuntimeError) as raised:
                _run(
                    [
                        "sh",
                        "-c",
                        descendant_script(marker, exit_code=0, closed_stdio=True),
                    ],
                    cwd=str(self.root),
                    timeout=30,
                )
        self.assertIs(raised.exception, boom)
        self.assertEqual(made["n"], 2, "the second reader start was never reached")
        self.assertEqual(len(leaders), 1)
        leader = leaders[0]
        self.assertIn(
            "pid", observed, "the fixture descendant never started; test is vacuous"
        )
        # Both the exact leader and the exact descendant must be gone.
        self.assertFalse(
            outlives(observed["pid"]),
            "a descendant survived a failed reader startup",
        )
        self.assertFalse(outlives(leader.pid), "the leader survived")
        self.assertEqual(
            install_module._live_process_group_members(
                leader, label="child command"
            ),
            (),
            "a group member survived a failed reader startup",
        )

    def test_hostile_build_output_is_sanitized_in_tail_and_error(self) -> None:
        # Build output is attacker-influenced and reaches a terminal both as
        # the returned tail and inside the timeout diagnostic.
        hostile = (
            r"\033[2J\033[1;31m"          # ANSI erase + colour
            r"\033]0;window-title\007"     # OSC window-title with BEL
            r"\033[?1049h"                 # alternate screen buffer
            "BUILD-MARKER-OK"
            r"\010\010\010"                # backspaces
            r"\r\n"
            r"\342\200\256"                # U+202E right-to-left override
            r"\000"                        # NUL
        )
        returncode, tail = _run_with_tail(
            ["sh", "-c", f"printf '{hostile}'"],
            cwd=str(self.root),
            env=dict(os.environ),
            timeout=30,
        )
        self.assertEqual(returncode, 0)
        self.assertIn("BUILD-MARKER-OK", tail)
        forbidden = ("\x1b", "\x07", "\x08", "\r", "\n", "\x00", "‮")
        for character in forbidden:
            self.assertNotIn(character, tail)

        # The same sanitizer must protect the timeout diagnostic, which
        # embeds the tail.
        with self.assertRaises(InstallError) as raised:
            _run_with_tail(
                ["sh", "-c", f"printf '{hostile}'; sleep 60"],
                cwd=str(self.root),
                env=dict(os.environ),
                timeout=2,
            )
        message = str(raised.exception)
        rendered = "".join(
            traceback.format_exception(
                type(raised.exception), raised.exception,
                raised.exception.__traceback__,
            )
        )
        self.assertIn("BUILD-MARKER-OK", message)
        for character in forbidden:
            self.assertNotIn(character, message)
        # A rendered traceback legitimately contains its own newlines, so only
        # the terminal-control bytes are forbidden there.
        for character in ("\x1b", "\x07", "\x08", "\x00", "‮"):
            self.assertNotIn(character, rendered)

    def test_post_exit_drain_is_bounded_against_an_always_ready_pipe(self) -> None:
        # Deterministic proof that the post-exit drain terminates by its own
        # bound rather than by winning a race against the writer. A real
        # saturating descendant may or may not keep the descriptor ready on any
        # given host; this stub always does, so an unbounded drain can never
        # leave it.
        blocks = {"count": 0}

        class AlwaysReady:
            def select(self, _timeout):
                return [("key", "events")]

        def absorb() -> bool:
            blocks["count"] += 1
            return True

        finished = threading.Event()

        def drain() -> None:
            install_module._drain_pending(AlwaysReady(), absorb)
            finished.set()

        worker = threading.Thread(target=drain, daemon=True)
        worker.start()
        # The bound is 64 blocks / 0.5s, so a correct drain returns almost
        # immediately. Keep the join short so an unbounded drain is reported as
        # a named assertion failure rather than having to be caught by an
        # outer watchdog.
        worker.join(timeout=5)
        # An unbounded drain leaves this thread running forever; assert rather
        # than let the suite hang.
        self.assertTrue(
            finished.is_set(),
            "the post-exit drain did not terminate against an always-ready pipe",
        )
        self.assertLessEqual(
            blocks["count"], install_module._POST_EXIT_DRAIN_BLOCKS
        )

    def test_drain_stream_records_a_mid_stream_read_failure(self) -> None:
        # Exercises the production helper itself, not a stand-in: restoring a
        # silent `except ...: pass` here must fail this test directly.
        for error in (OSError("read failed"), ValueError("stream invalidated")):
            with self.subTest(type(error).__name__):
                blocks = [b"captured-prefix"]

                class FakeStream:
                    def __enter__(self):
                        return self

                    def __exit__(self, *exc_info):
                        return False

                    def read(self, _size):
                        if blocks:
                            return blocks.pop(0)
                        raise error

                sink = bytearray()
                failures: list[BaseException] = []
                install_module._drain_stream(FakeStream(), sink, failures)

                self.assertEqual(bytes(sink), b"captured-prefix")
                self.assertEqual(len(failures), 1)
                self.assertIs(failures[0], error)

    def test_post_exit_drain_goes_through_the_bounded_helper(self) -> None:
        # The bounded-helper test proves `_drain_pending` terminates; this
        # proves the build path actually uses it. Replacing the call with an
        # inline exhaustive loop would leave the helper correct but unused,
        # and on a fast reader that regression can hide behind a won race.
        marker = self.root / "drain-callsite.pid"
        real_drain = install_module._drain_pending
        calls = {"n": 0}

        def recording_drain(poller, absorb, **kwargs):
            calls["n"] += 1
            return real_drain(poller, absorb, **kwargs)

        with mock.patch.object(install_module, "_drain_pending", recording_drain):
            returncode, _tail = _run_with_tail(
                [
                    "sh",
                    "-c",
                    f"sh -c 'echo $$ > \"{marker}\"; "
                    "exec dd if=/dev/zero bs=1M status=none' &\n"
                    "exit 0\n",
                ],
                cwd=str(self.root),
                env=dict(os.environ),
                timeout=30,
            )
        self.assertEqual(returncode, 0)
        self.assertGreaterEqual(
            calls["n"], 1, "the post-exit drain bypassed the bounded helper"
        )
        self.assertFalse(outlives(descendant_pid(marker)))

    def test_incomplete_capture_from_a_failing_reader_refuses(self) -> None:
        # A reader that fails after capturing a prefix stops running, so it is
        # not "still alive": liveness alone would let a truncated stdout be
        # returned as if it were the command's real output.
        real_drain = install_module._drain_stream

        def failing_drain(stream, sink, failures):
            try:
                sink.extend(stream.read(8))
            except (OSError, ValueError):
                pass
            failures.append(OSError("simulated mid-stream read failure"))

        with mock.patch.object(install_module, "_drain_stream", failing_drain):
            with self.assertRaises(InstallError) as raised:
                _run(
                    ["sh", "-c", "printf 'prefix-then-much-more-output'"],
                    cwd=str(self.root),
                    timeout=30,
                )
        message = str(raised.exception)
        self.assertIn("output could not be captured", message)
        # The refusal must not disclose the underlying error text or any path.
        for leaked in ("simulated mid-stream read failure", "OSError", str(self.root)):
            self.assertNotIn(leaked, message)
        self.assertIs(install_module._drain_stream, real_drain)

    def test_a_chatty_descendant_cannot_wedge_a_finished_build(self) -> None:
        # The descendant writes continuously, so the output descriptor is
        # always ready. A leader-exit check reachable only when the selector
        # idles would never run, and the finished build would block until the
        # command timeout.
        marker = self.root / "chatty.pid"
        # No sleep anywhere: several `dd` producers keep the descriptor ready
        # continuously. An earlier version of this test slept between writes,
        # which let the pipe go idle and so never exercised the gapless case.
        writers = "".join(
            "sh -c 'exec dd if=/dev/zero bs=1M status=none' &\n" for _ in range(7)
        )
        script = (
            f"sh -c 'echo $$ > \"{marker}\"; "
            "exec dd if=/dev/zero bs=1M status=none' &\n" + writers + "exit 0\n"
        )
        started = time.monotonic()
        returncode, _tail = _run_with_tail(
            ["sh", "-c", script],
            cwd=str(self.root),
            env=dict(os.environ),
            timeout=60,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(returncode, 0)
        self.assertLess(elapsed, 15, "a chatty descendant wedged a finished build")
        self.assertFalse(
            outlives(descendant_pid(marker)),
            "a chatty build descendant survived",
        )

    def _delayed_mutation_fixture(self) -> tuple[ContentSpec, dict[str, str]]:
        """A pinned Git spec whose build backgrounds a delayed self-append."""
        source = self.root / "mutating-source"
        source.mkdir()
        (source / "fixture").write_text("#!/bin/sh\nexit 0\n")
        (source / "fixture").chmod(0o755)
        run("git", "init", "--quiet", cwd=source)
        run("git", "config", "user.name", "Fixture", cwd=source)
        run("git", "config", "user.email", "fixture@example.invalid", cwd=source)
        run("git", "add", "fixture", cwd=source)
        run("git", "commit", "--quiet", "-m", "fixture", cwd=source)
        ref = run("git", "rev-parse", "HEAD", cwd=source)
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {"type": "git", "repository": str(source), "ref": ref},
                "binary": "fixture",
                # The build exits immediately while leaving a same-group helper
                # that rewrites the built binary a moment later. The helper
                # records its pid so tests can assert on its exact identity.
                "build": [
                    "sh",
                    "-c",
                    "sh -c 'echo $$ > "
                    f'"{self.root / "build-descendant.pid"}"'
                    "; sleep 2; echo mutated >> fixture' &\nexit 0\n",
                ],
            }
        )
        return spec, dict(os.environ, GIT_ALLOW_PROTOCOL="file")

    def test_no_build_descendant_can_mutate_content_after_selection(self) -> None:
        spec, env = self._delayed_mutation_fixture()
        installer = Installer(str(self.root / "data"), env=env)

        selected = Path(installer.ensure(spec))

        # Non-vacuity: the hostile descendant must actually have existed, or a
        # stable digest below would prove nothing at all.
        hostile = descendant_pid(self.root / "build-descendant.pid", timeout=10.0)
        self.assertGreater(hostile, 0)
        self.assertFalse(
            outlives(hostile),
            "the build descendant survived ensure() and could still mutate",
        )

        settled = selected.read_bytes()
        digest = hashlib.sha256(settled).hexdigest()
        # If a build helper outlived ensure(), it rewrites the selected file a
        # couple of seconds after the call already returned it as final.
        time.sleep(4)
        self.assertEqual(
            hashlib.sha256(selected.read_bytes()).hexdigest(),
            digest,
            "a surviving build descendant rewrote content after selection",
        )
        self.assertNotIn(b"mutated", selected.read_bytes())

    def test_the_install_lock_is_held_until_group_cleanup_finishes(self) -> None:
        spec, env = self._delayed_mutation_fixture()
        installer = Installer(str(self.root / "data"), env=env)
        events: list[str] = []
        seen_members: list[int] = []
        real_cleanup = install_module._terminate_remaining_process_group
        real_lock = install_module.Installer._install_lock

        def recording_cleanup(process, *, label="asset converter"):
            if label != install_module._BUILD_COMMAND_LABEL:
                return real_cleanup(process, label=label)
            # The leader is still unreaped here, so its group id is exact.
            members = install_module._live_process_group_members(
                process, label=label
            )
            if members:
                seen_members.extend(members)
                events.append("live-under-lock")
            real_cleanup(process, label=label)
            events.append("cleanup-complete")
            self.assertEqual(
                install_module._live_process_group_members(process, label=label),
                (),
                "a group member outlived cleanup while the lock was held",
            )

        @contextlib.contextmanager
        def recording_lock(self_installer, install_id):
            with real_lock(self_installer, install_id):
                yield
            events.append("lock-released")

        with mock.patch.object(
            install_module, "_terminate_remaining_process_group", recording_cleanup
        ), mock.patch.object(
            install_module.Installer, "_install_lock", recording_lock
        ):
            installer.ensure(spec)

        # Non-vacuity: if no build descendant was ever live under the lock,
        # this test proves nothing and must fail rather than pass quietly.
        self.assertIn(
            "live-under-lock",
            events,
            "no live build-group member existed under the lock; test is vacuous",
        )
        self.assertTrue(seen_members)
        for member in seen_members:
            self.assertFalse(outlives(member), f"group member {member} survived")
        self.assertIn("cleanup-complete", events)
        self.assertIn("lock-released", events)
        self.assertLess(
            events.index("live-under-lock"),
            events.index("cleanup-complete"),
            "cleanup was recorded before any member was observed live",
        )
        self.assertLess(
            events.index("cleanup-complete"),
            events.index("lock-released"),
            "the install lock was released before the build group was cleared",
        )

    def test_stalled_source_setup_is_bounded_and_leaves_no_residue(self) -> None:
        stub_bin = self.root / "bin"
        stub_bin.mkdir()
        pid_path = self.root / "descendant.pid"
        stub = stub_bin / "git"
        # The stub leaves a descendant behind: a timeout that killed only the
        # direct child would let this outlive the bounded source setup.
        stub.write_text(
            "#!/bin/sh\n"
            f"sh -c 'echo $$ > \"{pid_path}\"; exec sleep 60' &\n"
            "sleep 60\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        spec = ContentSpec.from_mapping(
            {
                "id": "fixture",
                "label": "Fixture",
                "source": {
                    "type": "git",
                    "repository": str(self.root / "unused-repository"),
                    "ref": "a" * 40,
                },
                "binary": "fixture",
            }
        )
        data = self.root / "data"
        environment = dict(
            os.environ,
            PATH=str(stub_bin) + os.pathsep + os.environ.get("PATH", os.defpath),
        )
        installer = Installer(str(data), env=environment, command_timeout=0.5)
        started = time.monotonic()
        with self.assertRaisesRegex(InstallError, "timed out"):
            installer.ensure(spec)
        self.assertLess(time.monotonic() - started, 30)
        self.assertFalse(
            any(path.name.startswith(".fixture.install-") for path in data.iterdir())
        )

        # The stub really did spawn a descendant ...
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not pid_path.exists():
            time.sleep(0.05)
        self.assertTrue(pid_path.exists(), "stub never spawned its descendant")
        descendant = int(pid_path.read_text(encoding="ascii").strip())
        # ... and the timeout killed the complete process group, not just the
        # direct child, so nothing is left holding the staging directory.
        alive = True
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                os.kill(descendant, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.05)
        self.assertFalse(
            alive, f"descendant {descendant} survived the source-setup timeout"
        )

    def test_json_loader_reports_malformed_catalog(self) -> None:
        path = self.root / "catalog.json"
        path.write_text(json.dumps({"schema_version": 5, "content": []}))
        with self.assertRaises(CatalogError):
            Catalog.load(path)


if __name__ == "__main__":
    unittest.main()
