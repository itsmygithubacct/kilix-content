from __future__ import annotations

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "src"))

from kilix_content import (  # noqa: E402
    Catalog,
    CatalogError,
    ContentSpec,
    InstallError,
    Installer,
    default_catalog,
    download,
    safe_extract_tar,
    safe_extract_zip,
)
from kilix_content.install import _rename_exchange  # noqa: E402


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
        self.assertGreaterEqual(len(catalog), 12)
        self.assertEqual(catalog.require("kilix-jpak").launch_mode, "terminal")
        self.assertEqual(catalog.require("kilix-rancher").binary,
                         "kilix-rancher")
        self.assertEqual(catalog.require("kilix-pong").icon, "pong")
        lights = catalog.require("kilix-lights")
        self.assertEqual(lights.binary, "bin/kilix-lights")
        self.assertIn("kitty-mouse", lights.capabilities)
        self.assertEqual(catalog.require("kilix-amp").launch_mode, "xpane")
        for entry in catalog:
            if entry.source_type == "git":
                self.assertEqual(len(entry.ref), 40)

    def test_catalog_rejects_mutable_refs_paths_and_duplicates(self) -> None:
        base = {
            "id": "fixture",
            "label": "Fixture",
            "source": {"type": "git", "repository": "fixture", "ref": "a" * 40},
            "binary": "fixture",
        }
        with self.assertRaises(CatalogError):
            ContentSpec.from_mapping({**base, "source": {**base["source"], "ref": "main"}})
        with self.assertRaises(CatalogError):
            ContentSpec.from_mapping({**base, "binary": "../fixture"})
        spec = ContentSpec.from_mapping(base)
        with self.assertRaises(CatalogError):
            Catalog((spec, spec))

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
            ["git", "-c", "protocol.file.allow=always", "submodule", "add", "--quiet",
             str(dependency), "third_party/dependency"],
            cwd=source, check=True, capture_output=True, text=True,
        )
        run("git", "commit", "--quiet", "-m", "fixture", cwd=source)
        return source, run("git", "rev-parse", "HEAD", cwd=source)

    def test_git_install_is_recursive_pinned_and_atomic(self) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping({
            "id": "fixture", "label": "Fixture",
            "source": {"type": "git", "repository": str(source), "ref": ref},
            "binary": "fixture",
        })
        data = self.root / "data"
        env = dict(os.environ, GIT_ALLOW_PROTOCOL="file")
        installer = Installer(str(data), env=env)
        executable = installer.ensure(spec)
        self.assertEqual(executable, str(data / "fixture" / "fixture"))
        self.assertTrue((data / "fixture" / "third_party/dependency/value.txt").is_file())
        self.assertEqual(installer.ready(spec), executable)
        self.assertFalse(any(path.name.startswith(".fixture.install-") for path in data.iterdir()))

        run("git", "remote", "set-url", "origin", str(source) + "-wrong", cwd=data / "fixture")
        self.assertIsNone(installer.ready(spec))
        run("git", "remote", "set-url", "origin", str(source), cwd=data / "fixture")
        with (data / "fixture" / "fixture").open("a") as stream:
            stream.write("# modified\n")
        self.assertIsNone(installer.ready(spec))
        with self.assertRaises(InstallError):
            installer.ensure(spec)

    def test_failed_git_fetch_leaves_no_selected_or_partial_tree(self) -> None:
        source, _ref = self._git_fixture()
        spec = ContentSpec.from_mapping({
            "id": "missing", "label": "Missing",
            "source": {"type": "git", "repository": str(source), "ref": "f" * 40},
            "binary": "fixture",
        })
        data = self.root / "data"
        installer = Installer(str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file"))
        with self.assertRaises(InstallError):
            installer.ensure(spec)
        self.assertFalse((data / "missing").exists())
        self.assertFalse(any(path.name.startswith(".missing.install-") for path in data.iterdir()))

    def test_interrupted_empty_git_init_is_replaced_atomically(self) -> None:
        source, ref = self._git_fixture()
        spec = ContentSpec.from_mapping({
            "id": "fixture", "label": "Fixture",
            "source": {"type": "git", "repository": str(source), "ref": ref},
            "binary": "fixture",
        })
        data = self.root / "data"
        interrupted = data / "fixture"
        interrupted.mkdir(parents=True)
        run("git", "init", "--quiet", cwd=interrupted)

        installer = Installer(str(data), env=dict(os.environ, GIT_ALLOW_PROTOCOL="file"))
        executable = installer.ensure(spec)

        self.assertEqual(executable, str(interrupted / "fixture"))
        self.assertEqual(run("git", "rev-parse", "HEAD", cwd=interrupted), ref)
        self.assertFalse(any(path.name.startswith(".fixture.install-") for path in data.iterdir()))

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

        with mock.patch("kilix_content.install._rename_exchange",
                        side_effect=observed_exchange):
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

        with mock.patch("kilix_content.install._rename_exchange",
                        side_effect=OSError(errno.ENOSYS, "unsupported")):
            with self.assertRaises(InstallError):
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

    def test_download_validates_checksum(self) -> None:
        source = self.root / "payload"
        source.write_bytes(b"payload")
        destination = self.root / "download"
        digest = hashlib.sha256(b"payload").hexdigest()
        download(source.as_uri(), str(destination), expected_sha256=digest)
        self.assertEqual(destination.read_bytes(), b"payload")
        with self.assertRaises(InstallError):
            download(source.as_uri(), str(destination), expected_sha256="0" * 64)
        self.assertFalse(destination.exists())

    def test_json_loader_reports_malformed_catalog(self) -> None:
        path = self.root / "catalog.json"
        path.write_text(json.dumps({"schema_version": 2, "content": []}))
        with self.assertRaises(CatalogError):
            Catalog.load(path)


if __name__ == "__main__":
    unittest.main()
