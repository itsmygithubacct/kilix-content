from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kilix_content.receipt import (
    _ASSET_V3_SCHEMA_SHA256,
    asset_v3_schema_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "src" / "kilix_content" / "contracts" / "kilix.content.asset-v3.schema.json"
PUBLIC_SCHEMA = ROOT / "contracts" / "kilix.content.asset-v3.schema.json"
KILIX_LICENSE_PIN = "a1f5d077f9ed26f61825b97c2487318bdd441fa1"
VENDORED = ROOT / "third_party" / "kilix-license"
VENDORED_OBJECTS = ROOT / "third_party" / "kilix-license.objects.json"
# Top-level kilix-license entries that are deliberately not vendored.
NOT_VENDORED = (
    ".gitignore",
    ".python-version",
    "Makefile",
    "PUBLICATION.md",
    "tests",
    "tools",
    "uv.lock",
)
VENDORED_FILE_COUNT = 135


def _git_oid(kind: bytes, body: bytes) -> str:
    return hashlib.sha1(kind + b" " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()


def _tree_bytes(entries: list[list[str]]) -> bytes:
    return b"".join(
        mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)
        for mode, name, oid in entries
    )


class ContractTests(unittest.TestCase):
    def test_packaged_schema_matches_public_copy(self) -> None:
        self.assertEqual(SCHEMA.read_bytes(), PUBLIC_SCHEMA.read_bytes())

    def test_frozen_schema_digest(self) -> None:
        actual = hashlib.sha256(asset_v3_schema_bytes()).hexdigest()
        self.assertEqual(actual, _ASSET_V3_SCHEMA_SHA256)

    def test_schema_flip_is_detected(self) -> None:
        payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
        payload["title"] = payload["title"] + "x"
        flipped = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.assertNotEqual(flipped, _ASSET_V3_SCHEMA_SHA256)

    def test_schema_declares_v3(self) -> None:
        payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(payload["properties"]["schema"]["const"], "kilix.content.asset/v3")

    def test_kilix_license_is_pinned_archive(self) -> None:
        pin = (ROOT / "third_party" / "kilix-license.pin").read_text(encoding="utf-8").strip()
        self.assertEqual(pin, KILIX_LICENSE_PIN)
        self.assertTrue(
            (ROOT / "third_party" / "kilix-license" / "src" / "kilix_license" / "data" / "records" / "small-en-us.json").is_file()
        )

    def test_vendored_kilix_license_is_the_pinned_git_archive(self) -> None:
        """Every vendored byte hashes up to the pinned commit (C2E-VERIFY F5).

        The recorded commit and tree objects must hash to the pin, and each
        vendored file to its blob id in them. git archive of the pin emits
        exactly those blobs (the tree has no .gitattributes), so a changed,
        missing or extra vendored file fails, and so does a changed record.
        tools/vendored_kilix_license.py --repo compares with git archive itself.
        """
        objects = json.loads(VENDORED_OBJECTS.read_text(encoding="utf-8"))
        self.assertEqual(objects["schema"], "kilix-content.vendored-git-objects/v1")
        self.assertEqual(objects["pin"], KILIX_LICENSE_PIN)
        self.assertEqual(tuple(objects["excluded_top_level"]), NOT_VENDORED)
        commit = objects["commit"].encode("utf-8")
        self.assertEqual(_git_oid(b"commit", commit), KILIX_LICENSE_PIN)
        first = commit.split(b"\n", 1)[0].decode("ascii")
        self.assertTrue(first.startswith("tree "), first)
        pinned: dict[str, str] = {}
        excluded: list[str] = []

        def walk(oid: str, prefix: str) -> None:
            entries = objects["trees"][oid]
            self.assertEqual(_git_oid(b"tree", _tree_bytes(entries)), oid, prefix or "/")
            for mode, name, child in entries:
                path = prefix + name
                self.assertNotIn(".gitattributes", name, path)
                if not prefix and name in NOT_VENDORED:
                    excluded.append(name)
                elif mode == "40000":
                    walk(child, path + "/")
                else:
                    self.assertIn(mode, ("100644", "100755"), path)
                    pinned[path] = child

        walk(first[len("tree ") :], "")
        self.assertEqual(sorted(excluded), sorted(NOT_VENDORED))
        vendored: dict[str, str] = {}
        for path in VENDORED.rglob("*"):
            relative = path.relative_to(VENDORED)
            if "__pycache__" in relative.parts:
                continue
            self.assertFalse(path.is_symlink(), relative)
            if path.is_file():
                vendored[relative.as_posix()] = _git_oid(b"blob", path.read_bytes())
        self.assertEqual(sorted(vendored), sorted(pinned))
        for path, oid in pinned.items():
            self.assertEqual(vendored[path], oid, path)
        self.assertEqual(len(vendored), VENDORED_FILE_COUNT)

    def test_repin_refuses_a_wrong_old_value_or_a_changed_vendored_tree(self) -> None:
        """--repin is the only way the pin moves, and it is guarded (C2f)."""
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-repin-"))
        for name in ("src", "tools", "third_party"):
            shutil.copytree(
                ROOT / name,
                scratch / name,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        pin_file = scratch / "third_party" / "kilix-license.pin"
        objects = scratch / "third_party" / "kilix-license.objects.json"
        before = (pin_file.read_bytes(), objects.read_bytes())
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        repo = ROOT.parent  # never read: every arm below fails before git runs

        def repin(new: str, old: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "tools/vendored_kilix_license.py",
                    "--repo",
                    str(repo),
                    "--repin",
                    new,
                    "--old",
                    old,
                ],
                cwd=scratch,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        other = "0" * 39 + "1"
        wrong = repin(other, "f" * 40)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("old-value guard failed", wrong.stderr)
        same = repin(KILIX_LICENSE_PIN, KILIX_LICENSE_PIN)
        self.assertNotEqual(same.returncode, 0)
        self.assertIn(f"already pinned to {KILIX_LICENSE_PIN}", same.stderr)
        short = repin("7104ea5c", KILIX_LICENSE_PIN)
        self.assertNotEqual(short.returncode, 0)
        self.assertIn("is not a 40-hex commit id", short.stderr)
        # A vendored file that no longer hashes up to the pin stops a re-pin:
        # the old bytes must be exactly the pin's before they are replaced.
        changelog = scratch / "third_party" / "kilix-license" / "CHANGELOG.md"
        original = changelog.read_bytes()
        changelog.write_bytes(original + b"planted\n")
        try:
            edited = repin(other, KILIX_LICENSE_PIN)
        finally:
            changelog.write_bytes(original)
        self.assertNotEqual(edited.returncode, 0)
        self.assertIn("is not the pinned blob", edited.stderr)
        self.assertEqual((pin_file.read_bytes(), objects.read_bytes()), before)
        # The offline check still passes on the untouched copy.
        clean = subprocess.run(
            [sys.executable, "tools/vendored_kilix_license.py"],
            cwd=scratch,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertIn(f"hash up to pin {KILIX_LICENSE_PIN}", clean.stdout)

    def test_make_pins_refuses_hand_edited_receipt_pins(self) -> None:
        """make pins (generator --check) gates receipt.py's pins (C2E-VERIFY F7)."""
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-pins-"))
        for name in ("src", "tools", "third_party"):
            shutil.copytree(
                ROOT / name,
                scratch / name,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        receipt = scratch / "src" / "kilix_content" / "receipt.py"
        original = receipt.read_text(encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = "src:third_party/kilix-license/src"
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        def check() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "tools/generate_upstream_records.py", "--check"],
                cwd=scratch,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        control = check()
        self.assertEqual(control.returncode, 0, control.stderr)
        for name in ("_CATALOG_SHA256", "_ASSET_V3_SCHEMA_SHA256"):
            match = re.search(rf'{name} = \(\n    "([0-9a-f]{{64}})"\n\)', original)
            self.assertIsNotNone(match, name)
            pinned = match.group(1)
            self.assertEqual(original.count(pinned), 1, name)
            edited = pinned[:-1] + ("0" if pinned[-1] != "0" else "1")
            receipt.write_text(original.replace(pinned, edited), encoding="utf-8")
            try:
                result = check()
            finally:
                receipt.write_text(original, encoding="utf-8")
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn(f"{name} in src/kilix_content/receipt.py is {edited}", result.stderr)
            self.assertIn(f"hash to {pinned}", result.stderr)
        self.assertEqual(check().returncode, 0)

    def test_make_pins_refuses_a_second_pin_assignment(self) -> None:
        """The runtime uses the last assignment; make pins read the first (C2E-FIX-VERIFY R5)."""
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-pins-twice-"))
        for name in ("src", "tools", "third_party"):
            shutil.copytree(
                ROOT / name,
                scratch / name,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        receipt = scratch / "src" / "kilix_content" / "receipt.py"
        original = receipt.read_text(encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = "src:third_party/kilix-license/src"
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        def check() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "tools/generate_upstream_records.py", "--check"],
                cwd=scratch,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(check().returncode, 0)
        for name in ("_CATALOG_SHA256", "_ASSET_V3_SCHEMA_SHA256"):
            match = re.search(rf'{name} = \(\n    "([0-9a-f]{{64}})"\n\)', original)
            self.assertIsNotNone(match, name)
            pinned = match.group(1)
            seconds = {
                # The verifier's shape: the runtime pin becomes all zeros.
                "zeros": f'\n{name} = "{"0" * 64}"\n',
                # Refused even when the second value is the right one.
                "same value": f'\n{name} = (\n    "{pinned}"\n)\n',
                "augmented": f'\n{name} += ""\n',
                # A counter that reads only top-level Assign/AugAssign targets
                # misses these two (C2E-FIX2-VERIFY T6, mutant N1).
                "annotated": f'\n{name}: str = "{"0" * 64}"\n',
                "inside an if": f'\nif True:\n    {name} = "{"0" * 64}"\n',
            }
            for label, second in seconds.items():
                with self.subTest(name=name, second=label):
                    receipt.write_text(original + second, encoding="utf-8")
                    try:
                        result = check()
                    finally:
                        receipt.write_text(original, encoding="utf-8")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{name} is bound 2 times in src/kilix_content/receipt.py",
                        result.stderr,
                    )
        self.assertEqual(check().returncode, 0)
