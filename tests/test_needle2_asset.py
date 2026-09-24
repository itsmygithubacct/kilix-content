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
BASE = f"https://huggingface.co/Cactus-Compute/needle2/resolve/{REVISION}"
APP_ASSETS = ("needle2", "needle2-runtime", "needle2-train")
WHEEL = "cactus_needle-2.0.4-py3-none-manylinux2014_x86_64.whl"


def _pin(asset_id: str) -> dict:
    path = ROOT / "tools" / "upstream-pins" / f"{asset_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


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
            if asset_id in APP_ASSETS:
                continue
            for row in asset["licenses"]:
                with self.subTest(asset=asset_id, licence=row["id"]):
                    record = self.records.by_digest(row["record_digest"])
                    self.assertEqual(record.determinations_sha256, release)

    def test_version_is_the_revision(self) -> None:
        self.assertEqual(self.spec.version, REVISION)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", self.spec.version))



class Needle2RuntimeAndTrainTests(unittest.TestCase):
    """needle2-runtime (libneedle.so, inside the upstream wheel) and needle2-train
    (the base checkpoint and tokenizer), owner direction 2026-09-22, round 2."""

    @classmethod
    def setUpClass(cls) -> None:
        catalog = default_catalog()
        cls.specs = {asset_id: catalog.require_asset(asset_id) for asset_id in APP_ASSETS}
        raw = json.loads(
            (ROOT / "src" / "kilix_content" / "catalog" / "plebian.json").read_text(encoding="utf-8")
        )
        cls.raw = {asset["id"]: asset for asset in raw["assets"]}
        cls.records = load_determined_records()

    def test_runtime_is_the_wheel_byte_exact(self) -> None:
        # Archive mode needs one top-level root and a wheel has two, so the
        # wheel itself is the member; the consumer reads needle/libneedle.so
        # out of the verified bytes.
        source = self.raw["needle2-runtime"]["source"]
        self.assertEqual(source["mode"], "upstream-files")
        self.assertEqual(source["fetch"], [{"path": WHEEL,
                                            "url": f"{BASE}/python/{WHEEL}"}])
        files = {item.path: item for item in self.specs["needle2-runtime"].files}
        self.assertEqual(sorted(files), [WHEEL, "notices/LICENSE-apache-2.0.txt"])
        [member] = _pin("needle2-runtime")["members"]
        self.assertEqual((files[WHEEL].sha256, files[WHEEL].bytes),
                         (member["sha256"], member["bytes"]))

    def test_train_is_the_checkpoint_and_tokenizer(self) -> None:
        wanted = ["checkpoints/needle2.pkl", "tokenizer/tokenizer.model",
                  "tokenizer/tokenizer.vocab"]
        source = self.raw["needle2-train"]["source"]
        self.assertEqual([item["path"] for item in source["fetch"]], wanted)
        self.assertEqual([item["url"] for item in source["fetch"]],
                         [f"{BASE}/{path}" for path in wanted])
        files = {item.path: item for item in self.specs["needle2-train"].files}
        self.assertEqual(sorted(files), sorted(wanted + ["notices/LICENSE-apache-2.0.txt"]))
        for member in _pin("needle2-train")["members"]:
            with self.subTest(path=member["path"]):
                self.assertEqual((files[member["path"]].sha256, files[member["path"]].bytes),
                                 (member["sha256"], member["bytes"]))

    def test_each_is_its_own_application_record_with_needle2s_licence(self) -> None:
        app_pin = _pinned("determinations-apps.sha256")
        base = self.records.by_digest(self.raw["needle2"]["licenses"][0]["record_digest"])
        digests = set()
        for asset_id in ("needle2-runtime", "needle2-train"):
            with self.subTest(asset=asset_id):
                [row] = self.raw[asset_id]["licenses"]
                record = self.records.by_digest(row["record_digest"])
                self.assertEqual(record.id, asset_id)
                self.assertEqual(record.determinations_sha256, app_pin)
                self.assertEqual((record.licensor, record.text_sha256, record.licence_text_id),
                                 (base.licensor, base.text_sha256, base.licence_text_id))
                self.assertEqual(self.raw[asset_id]["provider"], "kilix-needle")
                self.assertEqual(self.specs[asset_id].version, REVISION)
                digests.add(row["record_digest"])
        self.assertEqual(len(digests), 2)


if __name__ == "__main__":
    unittest.main()
