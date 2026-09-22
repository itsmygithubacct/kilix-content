"""The kilix-needle engine asset (owner direction 2026-09-22).

needle2 is an application model, not a release model. Its licence record lives
in kilix-license's application authority (determinations-apps.json), which has
its own pin, so adding it moved no release record digest: every other asset's
licence row still resolves to a record citing the release determinations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

from kilix_license.catalog import load_determined_records

from kilix_content import default_catalog

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "third_party" / "kilix-license" / "src" / "kilix_license" / "data"
PIN = json.loads((ROOT / "tools" / "upstream-pins" / "needle2.json").read_text(encoding="utf-8"))
REVISION = "32e9e3a93b205f786929697446ae669cf0a84579"


def _pinned(name: str) -> str:
    for line in (DATA / name).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            return line.split()[0]
    raise AssertionError(f"no pin in {name}")


class Needle2AssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = default_catalog().require_asset("needle2")
        cls.catalog = json.loads(
            (ROOT / "src" / "kilix_content" / "catalog" / "plebian.json").read_text(encoding="utf-8")
        )
        cls.raw = {asset["id"]: asset for asset in cls.catalog["assets"]}
        cls.records = load_determined_records()

    def test_the_engine_is_fetched_at_the_pinned_revision(self) -> None:
        [fetch] = self.raw["needle2"]["source"]["fetch"]
        self.assertEqual(fetch["path"], "needle")
        self.assertEqual(
            fetch["url"],
            f"https://huggingface.co/Cactus-Compute/needle2/resolve/{REVISION}/linux-x86_64/needle",
        )
        self.assertEqual(self.raw["needle2"]["source"]["mode"], "upstream-files")
        self.assertEqual(self.raw["needle2"]["provider"], "kilix-needle")

    def test_the_manifest_is_the_engine_and_its_notice(self) -> None:
        files = {item.path: item for item in self.spec.files}
        self.assertEqual(sorted(files), ["needle", "notices/LICENSE-apache-2.0.txt"])
        [member] = PIN["members"]
        self.assertEqual((files["needle"].sha256, files["needle"].bytes),
                         (member["sha256"], member["bytes"]))
        notice = (DATA / "texts" / files["notices/LICENSE-apache-2.0.txt"].sha256).read_bytes()
        self.assertEqual(hashlib.sha256(notice).hexdigest(),
                         files["notices/LICENSE-apache-2.0.txt"].sha256)

    def test_the_licence_row_is_the_application_record(self) -> None:
        [row] = self.raw["needle2"]["licenses"]
        record = self.records.by_digest(row["record_digest"])
        self.assertEqual(record.id, "needle2")
        self.assertEqual(record.determinations_sha256, _pinned("determinations-apps.sha256"))
        self.assertEqual(row["licensors"], ["Cactus Compute, Inc."])
        self.assertEqual((row["id"], row["decision"]), ("apache-2.0", "affirmative"))
        self.assertEqual(row["text_sha256"], record.text_sha256)

    def test_release_assets_still_cite_the_release_determinations(self) -> None:
        release = _pinned("determinations.sha256")
        for asset_id, asset in self.raw.items():
            if asset_id == "needle2":
                continue
            for row in asset["licenses"]:
                with self.subTest(asset=asset_id, licence=row["id"]):
                    record = self.records.by_digest(row["record_digest"])
                    self.assertEqual(record.determinations_sha256, release)

    def test_version_is_the_revision(self) -> None:
        self.assertEqual(self.spec.version, REVISION)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", self.spec.version))


if __name__ == "__main__":
    unittest.main()
