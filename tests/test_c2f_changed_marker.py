"""The changed-text marker is kilix-license's, and kilix-content shows it (SR-4).

kilix-content keeps no changed-policy scan of its own. `first_use.present_asset`
hands kilix-license the receipt store and the record index, so the behaviour
this repository owes its users is tested here through the screen it prints:

- a policy accepted for one record is marked when a sibling record shows a
  revised copy of the same text (the C2e keying could not see this);
- a receipt written before LIC4 is resolved through the record index;
- a character device or FIFO named like a receipt is never opened, and one
  swapped in after the check is never read (C2E-FIX2-VERIFY T1, T2).
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fake_store import FakeStore
from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.receipts import receipt_from_agreement
from kilix_license.records import RecordIndex
from screen_marker import changed_block, marker_lines

from kilix_content import default_catalog
from kilix_content.first_use import license_record_for, needs_agreement, present_asset
from kilix_content.receipt import _CATALOG_SHA256, release_digest

ROOT = Path(__file__).resolve().parents[1]
OLD_RECEIPTS = ROOT / "tests" / "data" / "receipts-d8e2c40a"
TERNARY = "bonsai-image-4b-ternary-gemlite"
BINARY = "bonsai-image-4b-binary-gemlite"
POLICY_SHA256 = "3fa706724776c03b2b6f2290de4bb09e7ba4dae239dfcfba27bac26f41d86e02"
POLICY_TEXT_ID = "bfl.ai/legal/usage-policy"
# Devices a receipt-shaped symlink could point at. /dev/ptmx blocks a read and
# hands out a pty; /dev/zero never ends. Neither may be opened by the screen.
DEVICES = ("/dev/ptmx", "/dev/zero", "/dev/null", "/dev/tty", "/dev/random")

# One child renders a packaged asset's screen with os.open, os.stat and os.read
# spied on, under a 4 GiB address-space cap. RACE swaps the named entry for a
# FIFO after its stat, which is the window the reader must survive (T2).
_SPY_CHILD = r"""
import json, os, resource, sys, tempfile
_soft, hard = resource.getrlimit(resource.RLIMIT_AS)
cap = 4 << 30 if hard == resource.RLIM_INFINITY else min(4 << 30, hard)
resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
from pathlib import Path
from fake_store import FakeStore
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_content import default_catalog
from kilix_content.first_use import license_record_for, present_asset
from screen_marker import changed_block

root, asset_id, race_name = sys.argv[1], sys.argv[2], sys.argv[3]
opened, raced, flags, read_per_open, fds = [], [], {}, {}, {}
real_open, real_stat, real_read = os.open, os.stat, os.read


def spy_open(path, how, *args, **kwargs):
    name = os.path.basename(os.fsdecode(path))
    opened.append(name)
    flags.setdefault(name, []).append(how)
    fd = real_open(path, how, *args, **kwargs)
    read_per_open.setdefault(name, []).append(0)
    fds[fd] = (name, len(read_per_open[name]) - 1)
    return fd


def racing_stat(path, *args, **kwargs):
    result = real_stat(path, *args, **kwargs)
    name = os.path.basename(os.fsdecode(path))
    if race_name and name == race_name and not raced:
        raced.append(name)  # a regular file at the check, a FIFO at the open
        os.unlink(path)
        os.mkfifo(path)
    return result


def spy_read(fd, count):
    data = real_read(fd, count)
    if fd in fds:
        name, index = fds[fd]
        read_per_open[name][index] += len(data)
    return data


records = load_determined_records()
spec = default_catalog().require_asset(asset_id)
texts = load_determined_texts(Path(tempfile.mkdtemp(prefix="kilix-content-spy-")))
record = license_record_for(spec, records)
store = FakeStore(root)
os.open, os.stat, os.read = spy_open, racing_stat, spy_read
try:
    screen = present_asset(spec, record, texts, receipts=store, records=records)
finally:
    os.open, os.stat, os.read = real_open, real_stat, real_read
print(json.dumps({
    "bytes": len(screen),
    "block": changed_block(screen),
    "opened": sorted(set(opened)),
    "raced": raced,
    "read_per_open": read_per_open,
    "flags": flags,
}))
"""


def _spy_child(case: unittest.TestCase, root: Path, asset_id: str, race: str = "") -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        str(path)
        for path in (
            ROOT / "src",
            ROOT / "third_party" / "kilix-license" / "src",
            ROOT / "tests" / "support",
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", _SPY_CHILD, str(root), asset_id, race],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    case.assertEqual(result.returncode, 0, result.stderr)
    return json.loads(result.stdout)


class SiblingPolicyMarkerTests(unittest.TestCase):
    """OD-AH: one policy, two records. Accepting it once does not re-accept it."""

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-c2f-marker-"))
        self.texts = load_determined_texts(self.scratch / "texts")
        self.records = load_determined_records()
        self.catalog = default_catalog()
        self.ternary = self.catalog.require_asset(TERNARY)
        self.binary = self.catalog.require_asset(BINARY)
        self.ternary_record = license_record_for(self.ternary, self.records)
        self.binary_record = license_record_for(self.binary, self.records)
        self.assertEqual(
            self.ternary_record.binding_conditions[0].text_sha256,
            self.binary_record.binding_conditions[0].text_sha256,
        )

    def _accept_ternary(self, store: FakeStore) -> None:
        agreement = capture_agreement(
            self.ternary_record, typed_agreement_line(self.ternary_record)
        )
        store.write(
            receipt_from_agreement(
                self.ternary_record,
                agreement,
                manifest_digest=self.ternary.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )

    def _revised_binary(self):
        condition = self.binary_record.binding_conditions[0]
        policy = self.texts.get(condition.text_sha256)
        planted = policy.replace(
            b"Last Revised on August 4", b"Last Revised on August 5"
        )
        self.assertEqual(len(planted), len(policy))
        self.assertEqual(
            sum(1 for left, right in zip(planted, policy) if left != right), 1
        )
        digest = self.texts.put(planted, label="planted-binary-policy")
        self.assertNotEqual(digest, POLICY_SHA256)
        revised = dataclasses.replace(
            self.binary_record,
            binding_conditions=(dataclasses.replace(condition, text_sha256=digest),),
        )
        spec = dataclasses.replace(
            self.binary,
            licenses=(
                dataclasses.replace(
                    self.binary.licenses[0], record_digest=revised.digest
                ),
            )
            + tuple(self.binary.licenses[1:]),
        )
        return planted, digest, revised, spec

    def _assert_sibling_marker(self, store: FakeStore) -> None:
        planted, digest, revised, spec = self._revised_binary()
        records = RecordIndex([revised, self.ternary_record])
        screen = present_asset(
            spec, revised, self.texts, receipts=store, records=records
        )
        self.assertEqual(
            changed_block(screen),
            marker_lines(
                "binding:bfl-usage-policy-binary",
                f"text:{POLICY_TEXT_ID}",
                (POLICY_SHA256,),
                (self.ternary_record.id,),
                digest,
            ),
        )
        # The marker precedes the revised text, and the accepted text is gone.
        self.assertIn(b"=== binding:bfl-usage-policy-binary ===\n" + planted, screen)
        self.assertLess(
            screen.index(b"=== changed since your last acceptance ==="),
            screen.index(b"=== binding:bfl-usage-policy-binary ==="),
        )
        self.assertNotIn(self.texts.get(POLICY_SHA256), screen)
        # Presentation grants nothing: the revised binary still needs agreement.
        self.assertTrue(needs_agreement(spec, records=records, store=store))

    def test_a_policy_accepted_under_ternary_is_changed_when_binary_revises_it(
        self,
    ) -> None:
        store = FakeStore(self.scratch / "store-lic4")
        self._accept_ternary(store)
        self._assert_sibling_marker(store)

    def test_the_same_holds_for_a_receipt_written_before_lic4(self) -> None:
        store = FakeStore(self.scratch / "store-old")
        name = (
            f"{self.ternary_record.digest}-{self.ternary.manifest_digest}.json"
        )
        payload = (OLD_RECEIPTS / name).read_bytes()
        self.assertNotIn(b"binding_text_ids", payload)
        (store.root / name).write_bytes(payload)
        self._assert_sibling_marker(store)

    def test_an_unrevised_sibling_shows_no_marker(self) -> None:
        """Control: the same store, the binary record as it stands."""
        store = FakeStore(self.scratch / "store-control")
        self._accept_ternary(store)
        screen = present_asset(
            self.binary,
            self.binary_record,
            self.texts,
            receipts=store,
            records=self.records,
        )
        self.assertEqual(changed_block(screen), [])
        self.assertTrue(
            needs_agreement(self.binary, records=self.records, store=store)
        )


class ScanHazardTests(unittest.TestCase):
    """C2E-FIX2-VERIFY T1 and T2, through the delegated screen."""

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-c2f-hazard-"))
        self.records = load_determined_records()
        self.catalog = default_catalog()
        self.spec = self.catalog.require_asset(TERNARY)
        self.record = license_record_for(self.spec, self.records)
        self.texts = load_determined_texts(self.scratch / "texts")
        self.store = FakeStore(self.scratch / "receipts")
        agreement = capture_agreement(self.record, typed_agreement_line(self.record))
        self.receipt = receipt_from_agreement(
            self.record,
            agreement,
            manifest_digest=self.spec.manifest_digest,
            release_digest=release_digest(),
            catalogue_digest=_CATALOG_SHA256,
        )
        self.receipt_name = self.store.write(self.receipt).name

    def test_a_character_device_named_like_a_receipt_is_never_opened(self) -> None:
        """T1: pinned for devices, not only for FIFOs, and not via the read bound."""
        planted = {}
        for device in DEVICES:
            if not Path(device).exists():
                continue
            self.assertTrue(
                stat.S_ISCHR(os.stat(device).st_mode), device
            )  # the shape this test claims
            name = f"0000-planted{device.replace('/', '-')}.json"
            os.symlink(device, self.store.root / name)
            planted[name] = device
        fifo = "0000-planted-fifo.json"
        os.mkfifo(self.store.root / fifo)
        planted[fifo] = "fifo"
        link = "0000-planted-fifo-symlink.json"
        os.symlink(self.store.root / fifo, self.store.root / link)
        planted[link] = "fifo symlink"
        self.assertGreaterEqual(len(planted), 4)
        result = _spy_child(self, self.store.root, TERNARY)
        self.assertGreater(result["bytes"], 0)
        for name, what in planted.items():
            self.assertNotIn(name, result["opened"], f"{what} was opened")
        self.assertIn(self.receipt_name, result["opened"])
        self.assertEqual(result["block"], [])
        for name in planted:
            self.assertTrue((self.store.root / name).is_symlink() or name == fifo)

    def test_a_fifo_swapped_in_after_the_check_is_never_read(self) -> None:
        """T2: the stat says regular, the open finds a FIFO. It must not block."""
        result = _spy_child(self, self.store.root, TERNARY, race=self.receipt_name)
        self.assertEqual(result["raced"], [self.receipt_name], "the race did not fire")
        self.assertIn(self.receipt_name, result["opened"])
        self.assertEqual(
            result["read_per_open"].get(self.receipt_name), [0], "bytes read from a FIFO"
        )
        for how in result["flags"][self.receipt_name]:
            self.assertTrue(how & os.O_NONBLOCK, "the open could block")
            self.assertTrue(how & os.O_NOCTTY, "the open could take a terminal")
        self.assertGreater(result["bytes"], 0)
        self.assertTrue(stat.S_ISFIFO(os.stat(self.store.root / self.receipt_name).st_mode))

    def test_the_control_receipt_is_read_when_nothing_is_planted(self) -> None:
        """Control: with no hazard the same child reads the valid receipt."""
        result = _spy_child(self, self.store.root, TERNARY)
        self.assertIn(self.receipt_name, result["opened"])
        self.assertGreater(sum(result["read_per_open"][self.receipt_name]), 0)


if __name__ == "__main__":
    unittest.main()
