from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

import kilix_content
from kilix_content import (
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
from kilix_content.install import _rename_exchange


def run(*argv: str, cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


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
        self.assertEqual(files.require_action("open").argv, ("--open",))
        self.assertIn("application/pdf", pdf_conversion.accepts)
        self.assertTrue(catalog.require("kilix-session-center").lifecycle.degrades_inplace)
        self.assertEqual(catalog.require("kilix-model-store").command,
                         ("kilix", "bonsai"))
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
        with self.assertRaises(InstallError) as raised:
            download((first, last), str(destination))
        self.assertIn("last-absent", str(raised.exception))
        self.assertNotIn("first-absent", str(raised.exception))
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

    def test_json_loader_reports_malformed_catalog(self) -> None:
        path = self.root / "catalog.json"
        path.write_text(json.dumps({"schema_version": 4, "content": []}))
        with self.assertRaises(CatalogError):
            Catalog.load(path)


if __name__ == "__main__":
    unittest.main()
