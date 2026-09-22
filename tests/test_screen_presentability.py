"""Every packaged first-use screen, run through the consumer's terminal guard.

`kilix models install <id>` renders this repository's first-use screen and,
before writing a byte of it to the terminal, runs it through a guard in
`config/content_models.py`: bounded, UTF-8, and free of Unicode category
`Cc`/`Cf`/`Zl`/`Zp` outside `_SAFE_CONTROLS = "\\n\\t"`. A screen that fails it
is refused with `SetupError: ... contains unsafe terminal controls`, **before
the prompt**, so the asset cannot be installed at all.

Nothing here rendered all 27 packaged screens through that rule, so the one
asset that fails it -- `bonsai-8b` -- was only found by driving a real install
on a pty. This module is the rule, applied to every asset, so the next screen
that acquires a control character fails here instead of at a user's terminal.

**The guard is a copy, and deliberately so.** kilix owns the canonical rule and
this repository cannot import it: the consumer is the component that pins *us*.
The copy is pinned to kilix `14344ec3` `config/content_models.py` and restated
below with its constants, so a reader can diff the two by eye. The report for
this wave asks that kilix publish the rule for consumers instead; until it does,
a copy that is named as one is better than 27 screens nobody checks.

**Why this module ships a declared exception rather than a clean pass.**
`bonsai-8b`'s screen carries three CR characters. They are not an accident and
they are not ours: they are in the pinned licence authority's shipped statement
blob `91ddaf3c...`, which is a byte-exact quotation of an upstream `NOTICE.txt`
spanning bytes 3..171 of lines 1..4 of a file whose sha256 the determination
records -- and whose own `note` field says, in as many words, "NOTICE.txt begins
with a UTF-8 BOM (excluded from the span) and uses CRLF line ends (kept)". So
two deliberate policies collide: the authority quotes upstream notices
byte-exactly, and the consumer refuses to write a CR to a terminal during
consent, because a CR can overwrite the line the reader just read.

`third_party/kilix-license/` is hash-chained to the pinned authority commit by
`third_party/kilix-license.objects.json` -- editing a vendored byte fails
`tests/test_contracts.py` -- so this repository cannot fix the data, and
widening the consumer's guard is the wrong fix for the reason above. The
exception is therefore recorded here, with the exact blob and the exact code
point, and is asserted by **set equality**: a new offender fails, and so does
the removal of this one, which forces the entry out at the moment the authority
is re-vendored.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unicodedata
import unittest

from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.texts import TextStore

from fake_store import FakeStore
from kilix_content import verified_packaged_catalog
from kilix_content.first_use import license_record_for, present_asset

ROOT = Path(__file__).resolve().parents[1]
LICENSE_DATA = (
    ROOT / "third_party" / "kilix-license" / "src" / "kilix_license" / "data"
)

# --- kilix config/content_models.py @ 14344ec3, restated ---------------------
MAX_SCREEN = 1024 * 1024
SAFE_CONTROLS = "\n\t"
UNSAFE_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")


class ScreenRefused(Exception):
    """Stands in for the consumer's SetupError."""


def checked(payload: bytes, what: str) -> bytes:
    if not payload:
        raise ScreenRefused(f"{what} is empty")
    if len(payload) > MAX_SCREEN:
        raise ScreenRefused(f"{what} exceeds the byte limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise ScreenRefused(f"{what} is not UTF-8 text") from error
    if any(
        unicodedata.category(char) in UNSAFE_CATEGORIES
        and char not in SAFE_CONTROLS
        for char in text
    ):
        raise ScreenRefused(f"{what} contains unsafe terminal controls")
    return payload
# --- end of the copied rule --------------------------------------------------


def offenders(payload: bytes) -> tuple[str, ...]:
    """Every code point in `payload` the rule above refuses, sorted."""
    return tuple(
        sorted(
            {
                char
                for char in payload.decode("utf-8")
                if unicodedata.category(char) in UNSAFE_CATEGORIES
                and char not in SAFE_CONTROLS
            }
        )
    )


# asset id -> (the shipped text blob that carries them, the code points).
# Set equality is asserted against this, so it fails in both directions.
KNOWN_UNPRESENTABLE = {
    "bonsai-8b": (
        "91ddaf3c398656e6b3189043e9758328d29d7081c0265567976d56940b2a7761",
        ("\r",),
    ),
}
PLANT_INTO = "bonsai-27b"  # a different record, and the CRLF one's sibling


class ScreenPresentabilityTests(unittest.TestCase):
    """Render every packaged screen; the catalogue is verified before parsing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-screens-"))
        cls.catalog = verified_packaged_catalog()
        cls.records = load_determined_records()
        cls.texts = load_determined_texts(cls.scratch / "texts")
        cls.receipts = FakeStore(cls.scratch / "receipts")

    def render(self, spec, texts=None) -> bytes:
        record = license_record_for(spec, self.records)
        return present_asset(
            spec,
            record,
            texts if texts is not None else self.texts,
            receipts=self.receipts,
            records=self.records,
        )

    def spec_for(self, asset_id: str):
        return {item.asset_id: item for item in self.catalog.assets}[asset_id]

    def test_every_packaged_screen_is_rendered_and_only_the_declared_one_refuses(
        self,
    ) -> None:
        refused: dict[str, tuple[str, ...]] = {}
        rendered = 0
        for spec in self.catalog.assets:
            rendered += 1
            payload = self.render(spec)
            self.assertTrue(payload, spec.asset_id)
            try:
                checked(payload, f"first-use screen for {spec.asset_id}")
            except ScreenRefused:
                refused[spec.asset_id] = offenders(payload)
        self.assertEqual(rendered, len(self.catalog.assets))
        self.assertGreaterEqual(rendered, 27)
        self.assertEqual(
            refused,
            {
                asset_id: code_points
                for asset_id, (_blob, code_points) in KNOWN_UNPRESENTABLE.items()
            },
            "a packaged first-use screen changed its presentability: a new "
            "refusal is a release defect, and a refusal that disappeared means "
            "the declared exception in KNOWN_UNPRESENTABLE must be removed",
        )

    def test_the_declared_exception_names_the_blob_that_carries_it(self) -> None:
        """The exception is pinned to a blob, not merely to an asset id.

        Without this, the authority could ship the same asset with a different
        offending text and the set-equality assertion above would still pass.
        """
        for asset_id, (blob, code_points) in KNOWN_UNPRESENTABLE.items():
            with self.subTest(asset=asset_id):
                record = license_record_for(self.spec_for(asset_id), self.records)
                statement_blobs = {item.text_sha256 for item in record.statements}
                self.assertIn(blob, statement_blobs)
                self.assertEqual(
                    offenders(self.texts.get(blob)), code_points
                )

    def test_exactly_one_shipped_licence_text_carries_a_refused_code_point(
        self,
    ) -> None:
        """Survey the authority's whole text store, not just what 27 screens reach."""
        carriers = {}
        surveyed = set()
        for path in sorted((LICENSE_DATA / "texts").iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            surveyed.add(path.name)
            found = offenders(path.read_bytes())
            if found:
                carriers[path.name] = found
        # Bound the survey by the records rather than by a typed count: every
        # text any record binds must have been read. A count would drift, and
        # an empty directory would otherwise read as "no offenders".
        cited = {
            item.text_sha256
            for record in self.records
            for item in (
                *record.statements,
                *record.advisories,
                *record.binding_conditions,
            )
        } | {record.text_sha256 for record in self.records}
        self.assertGreaterEqual(len(cited), len(self.catalog.assets))
        self.assertEqual(cited - surveyed, set())
        self.assertEqual(
            carriers,
            {blob: code_points for blob, code_points in KNOWN_UNPRESENTABLE.values()},
        )

    def test_the_rule_catches_a_control_character_planted_in_another_record(
        self,
    ) -> None:
        """Plant into a different record's own text and show the screen refuses.

        The plant goes into a scratch text store, never the vendored tree, and
        the same screen is rendered from the shipped store first, so the pass
        and the failure differ by exactly the planted byte.
        """
        spec = self.spec_for(PLANT_INTO)
        record = license_record_for(spec, self.records)
        self.assertNotIn(PLANT_INTO, KNOWN_UNPRESENTABLE)

        clean = self.render(spec)
        self.assertEqual(offenders(clean), ())
        checked(clean, "control arm")

        for planted in ("\r", "\x1b", "\x07", " ", "​"):
            with self.subTest(code_point=hex(ord(planted))):
                scratch = Path(
                    tempfile.mkdtemp(prefix="plant-", dir=str(self.scratch))
                )
                store = TextStore(scratch)
                for path in sorted((LICENSE_DATA / "texts").iterdir()):
                    if path.is_file() and not path.name.startswith("."):
                        store.put(path.read_bytes(), label=path.name)
                target = record.statements[0].text_sha256
                good = store.get(target)
                # Same digest, different bytes: the screen renderer asks the
                # store for `target`, so the planted bytes must answer to it.
                (scratch / target).write_bytes(
                    good.replace(b"\n", planted.encode("utf-8") + b"\n", 1)
                )
                store_bytes = (scratch / target).read_bytes()
                self.assertNotEqual(store_bytes, good)
                payload = clean.replace(good, store_bytes)
                self.assertNotEqual(payload, clean)
                self.assertIn(planted, payload.decode("utf-8"))
                with self.assertRaises(ScreenRefused) as raised:
                    checked(payload, f"first-use screen for {PLANT_INTO}")
                self.assertIn("unsafe terminal controls", str(raised.exception))

    def test_the_rule_also_refuses_an_empty_and_an_oversized_screen(self) -> None:
        """The other two arms of the copied rule, so none of it is unexercised."""
        with self.assertRaises(ScreenRefused):
            checked(b"", "empty")
        with self.assertRaises(ScreenRefused):
            checked(b"a" * (MAX_SCREEN + 1), "oversized")
        checked(b"a" * MAX_SCREEN, "at the limit")

    def test_every_packaged_screen_is_far_inside_the_byte_limit(self) -> None:
        largest = max(len(self.render(spec)) for spec in self.catalog.assets)
        self.assertLess(largest * 4, MAX_SCREEN)


if __name__ == "__main__":
    unittest.main()
