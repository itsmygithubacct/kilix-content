"""Every packaged first-use screen, run through the consumer's terminal guard.

`kilix models install <id>` renders this repository's first-use screen and,
before writing a byte of it to the terminal, runs it through a guard in
`config/content_models.py`: bounded, UTF-8, and free of Unicode category
`Cc`/`Cf`/`Zl`/`Zp` outside `_SAFE_CONTROLS = "\\n\\t"`. A screen that fails it
is refused with `SetupError: ... contains unsafe terminal controls`, **before
the prompt**, so the asset cannot be installed at all.

Nothing here rendered all 27 packaged screens through that rule, so the one
asset that failed it -- `bonsai-8b` -- was only found by driving a real install
on a pty. This module is the rule, applied to every asset, so the next screen
that acquires a control character fails here instead of at a user's terminal.

**The guard is a copy, and deliberately so.** kilix owns the canonical rule and
this repository cannot import it: the consumer is the component that pins *us*.
The copy is pinned to kilix `14344ec3` `config/content_models.py` and restated
below with its constants, so a reader can diff the two by eye. The report for
that wave asks that kilix publish the rule for consumers instead; until it does,
a copy that is named as one is better than 27 screens nobody checks.

**What `bonsai-8b` was, and what OD-BT decided.** Its screen carried three CR
characters. They were not an accident and they were not ours: they are in the
pinned licence authority's shipped statement blob
`91ddaf3c398656e6b3189043e9758328d29d7081c0265567976d56940b2a7761`, a byte-exact
quotation of an upstream `NOTICE.txt` spanning bytes 3..171 of lines 1..4 of a
file whose sha256 the determination records -- and whose own `note` field says,
in as many words, "NOTICE.txt begins with a UTF-8 BOM (excluded from the span)
and uses CRLF line ends (kept)". Two deliberate policies collided: the authority
quotes upstream notices byte-exactly, and the consumer refuses to write a CR to
a terminal during consent, because a CR can overwrite the line the reader just
read.

**OD-BT resolves it in the renderer, at display time only**:
`first_use.crlf_to_lf` turns CRLF into LF in the bytes `present_asset` returns,
and the guard runs on exactly those bytes. Nothing on disk changes -- the stored
quotation is still byte-exact, still CRLF, and its digest has not moved. This
module asserts both halves: `KNOWN_UNPRESENTABLE` is now **empty**, and
`CRLF_QUOTATION` records the blob that still carries CRLF **on disk**, so a
later wave that strips the data has to come here and say so.

**A bare CR is still refused, and that is the point.** A lone carriage return
returns the cursor and lets what follows overwrite the line the reader just
read. Normalising CRLF must not become a licence to pass any CR, so the plant
tests below drive a bare CR, a `\\r\\r\\n`, an escape, a bell, a line separator
and a zero-width space through the **real renderer** -- not through a payload
this module patched afterwards -- and every one of them is still refused.

**A future record that arrives with CRLF** therefore installs: its line endings
are normalised for display and nothing else about it changes. A future record
that arrives with a **bare** CR, or with any other `Cc`/`Cf`/`Zl`/`Zp`
character, still fails here and still cannot be installed, which is the outcome
those characters deserve.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import tempfile
import unicodedata
import unittest

from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.records import Statement
from kilix_license.texts import TextStore

from fake_store import FakeStore
from kilix_content import verified_packaged_catalog
from kilix_content.first_use import crlf_to_lf, license_record_for, present_asset

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
# Set equality is asserted against this, so it fails in both directions. OD-BT
# emptied it: a screen that refuses is now a release defect with no exception.
KNOWN_UNPRESENTABLE: dict[str, tuple[str, tuple[str, ...]]] = {}

# Provenance, asserted separately from presentability: this shipped blob still
# carries its upstream CRLF **on disk**, and must, because it is a byte-pinned
# quotation. OD-BT changed the renderer, not the data. If a later wave does
# strip the data, this is the assertion that makes it say so here.
CRLF_QUOTATION = {
    "asset": "bonsai-8b",
    "blob": "91ddaf3c398656e6b3189043e9758328d29d7081c0265567976d56940b2a7761",
    "carriage_returns": 3,
}

PLANT_INTO = "bonsai-27b"  # a different record, and the CRLF one's sibling
PLANT_MARKER = b"[planted]"


class ScreenPresentabilityTests(unittest.TestCase):
    """Render every packaged screen; the catalogue is verified before parsing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-screens-"))
        cls.catalog = verified_packaged_catalog()
        cls.records = load_determined_records()
        cls.texts = load_determined_texts(cls.scratch / "texts")
        cls.receipts = FakeStore(cls.scratch / "receipts")

    def render(self, spec, texts=None, record=None) -> bytes:
        return present_asset(
            spec,
            record if record is not None else license_record_for(spec, self.records),
            texts if texts is not None else self.texts,
            receipts=self.receipts,
            records=self.records,
        )

    def spec_for(self, asset_id: str):
        return {item.asset_id: item for item in self.catalog.assets}[asset_id]

    def shipped_store(self) -> TextStore:
        """A scratch copy of every shipped text, for planting into."""
        store = TextStore(Path(tempfile.mkdtemp(prefix="plant-", dir=str(self.scratch))))
        for path in sorted((LICENSE_DATA / "texts").iterdir()):
            if path.is_file() and not path.name.startswith("."):
                store.put(path.read_bytes(), label=path.name)
        return store

    def planted_render(self, spec, planted: bytes) -> tuple[bytes, bytes]:
        """Render `spec`'s screen with its first statement text replaced.

        The planted bytes are stored under **their own** digest and a record
        that names that digest is rendered, so the screen under test comes out
        of `present_asset` itself -- the real renderer, CRLF normalisation and
        all. Patching an already-rendered payload would test the guard while
        stepping around the very step OD-BT added, which is the
        normalise-here-check-there shape this wave exists to avoid. Nothing is
        written to the vendored tree.
        """
        record = license_record_for(spec, self.records)
        store = self.shipped_store()
        target = record.statements[0].text_sha256
        good = store.get(target)
        mutated = good.replace(b"\n", b"\n" + planted + PLANT_MARKER, 1)
        self.assertNotEqual(mutated, good)
        digest = store.put(mutated, label="planted")
        self.assertNotEqual(digest, target)
        planted_record = dataclasses.replace(
            record,
            statements=(
                Statement(id=record.statements[0].id, text_sha256=digest),
                *record.statements[1:],
            ),
        )
        return self.render(spec, texts=store, record=planted_record), mutated

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
        """Any exception is pinned to a blob, not merely to an asset id.

        `KNOWN_UNPRESENTABLE` is empty under OD-BT, so this loop guards a
        future entry rather than a present one: without it, the authority could
        ship the same asset with a different offending text and the
        set-equality assertion above would still pass.
        """
        for asset_id, (blob, code_points) in KNOWN_UNPRESENTABLE.items():
            with self.subTest(asset=asset_id):
                record = license_record_for(self.spec_for(asset_id), self.records)
                statement_blobs = {item.text_sha256 for item in record.statements}
                self.assertIn(blob, statement_blobs)
                self.assertEqual(
                    offenders(self.texts.get(blob)), code_points
                )

    def test_the_byte_pinned_quotation_is_still_crlf_on_disk(self) -> None:
        """OD-BT changed the renderer. The stored quotation did not move."""
        blob = CRLF_QUOTATION["blob"]
        stored = (LICENSE_DATA / "texts" / blob).read_bytes()
        self.assertEqual(stored.count(b"\r"), CRLF_QUOTATION["carriage_returns"])
        self.assertEqual(stored.count(b"\r\n"), CRLF_QUOTATION["carriage_returns"])
        self.assertEqual(offenders(stored), ("\r",))
        record = license_record_for(
            self.spec_for(CRLF_QUOTATION["asset"]), self.records
        )
        self.assertIn(blob, {item.text_sha256 for item in record.statements})
        self.assertEqual(self.texts.get(blob), stored)

    def test_the_crlf_asset_is_presentable_and_only_its_line_endings_changed(
        self,
    ) -> None:
        """`bonsai-8b` installs, and the screen still quotes every word."""
        spec = self.spec_for(CRLF_QUOTATION["asset"])
        screen = self.render(spec)
        checked(screen, f"first-use screen for {spec.asset_id}")
        self.assertEqual(offenders(screen), ())
        self.assertNotIn(b"\r", screen)
        stored = self.texts.get(CRLF_QUOTATION["blob"])
        self.assertIn(b"\r\n", stored)
        self.assertNotIn(stored, screen)
        self.assertIn(crlf_to_lf(stored), screen)
        # A line ending changed; not a word, and not a line.
        self.assertEqual(
            stored.replace(b"\r\n", b"\n").splitlines(),
            crlf_to_lf(stored).splitlines(),
        )
        self.assertEqual(len(crlf_to_lf(stored)), len(stored) - stored.count(b"\r\n"))

    def test_crlf_becomes_lf_and_a_bare_carriage_return_does_not(self) -> None:
        """The rule itself, including the case that must NOT be normalised."""
        self.assertEqual(crlf_to_lf(b"a\r\nb"), b"a\nb")
        self.assertEqual(crlf_to_lf(b"a\r\n\r\nb"), b"a\n\nb")
        self.assertEqual(crlf_to_lf(b"a\rb"), b"a\rb")
        self.assertEqual(crlf_to_lf(b"a\r"), b"a\r")
        self.assertEqual(crlf_to_lf(b""), b"")
        self.assertEqual(crlf_to_lf(b"a\nb"), b"a\nb")
        # One left-to-right pass over non-overlapping matches. A REPEATED
        # substitution would take this to b"a\nb" and admit the bare CR that
        # the guard exists to refuse; the single pass leaves a CR behind, and
        # the guard then refuses the payload.
        self.assertEqual(crlf_to_lf(b"a\r\r\nb"), b"a\r\nb")
        with self.assertRaises(ScreenRefused):
            checked(b"a\r\r\nb".replace(b"\r\n", b"\n"), "a bare CR before a CRLF")
        for payload in (b"a\rb", b"a\r", b"a\r\r\nb"):
            with self.subTest(payload=payload):
                with self.assertRaises(ScreenRefused):
                    checked(crlf_to_lf(payload), "a bare CR")

    def test_normalising_bytes_is_the_same_as_normalising_text(self) -> None:
        """UTF-8 is self-synchronising, so the byte form is not an approximation."""
        sample = "ascii\r\né中\U0001f600\r\nbare\rtail\r\n end"
        self.assertEqual(
            crlf_to_lf(sample.encode("utf-8")),
            sample.replace("\r\n", "\n").encode("utf-8"),
        )
        for code_point in range(0x110000):
            char = chr(code_point)
            if unicodedata.category(char) == "Cs":
                continue
            encoded = char.encode("utf-8")
            if len(encoded) > 1:
                self.assertNotIn(b"\r", encoded)
                self.assertNotIn(b"\n", encoded)
                break

    def test_the_guard_runs_on_exactly_the_bytes_that_will_be_displayed(
        self,
    ) -> None:
        """No second copy: what `present_asset` returns is what is checked.

        The consumer writes the bytes the guard returned, and the guard returns
        its argument unchanged, so normalising inside `present_asset` is the
        only place it can happen without the checked bytes and the written
        bytes drifting apart.
        """
        for spec in self.catalog.assets:
            with self.subTest(asset=spec.asset_id):
                payload = self.render(spec)
                self.assertNotIn(b"\r\n", payload)
                self.assertIs(checked(payload, spec.asset_id), payload)

    def test_exactly_one_shipped_licence_text_carries_a_refused_code_point(
        self,
    ) -> None:
        """Survey the authority's whole text store, not just what 27 screens reach.

        This is an **on-disk** survey and it is deliberately unchanged by OD-BT:
        the quotation still carries CRLF in the store. What changed is that the
        screen rendered from it is presentable.
        """
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
        self.assertEqual(carriers, {CRLF_QUOTATION["blob"]: ("\r",)})

    def test_the_rule_catches_a_control_character_planted_in_another_record(
        self,
    ) -> None:
        """Plant into a different record's own text and show the screen refuses.

        Every arm renders through `present_asset`, so normalisation happens to
        the planted bytes exactly as it happens to shipped ones, and the clean
        arm is rendered from the same scratch store first -- pass and failure
        differ by the planted bytes and nothing else.
        """
        spec = self.spec_for(PLANT_INTO)
        self.assertNotIn(PLANT_INTO, KNOWN_UNPRESENTABLE)

        clean = self.render(spec, texts=self.shipped_store())
        self.assertEqual(clean, self.render(spec))
        self.assertEqual(offenders(clean), ())
        checked(clean, "control arm")

        # A bare CR, a CR that precedes a CRLF, an escape, a bell, a line
        # separator and a zero-width space. `PLANT_MARKER` follows the planted
        # bytes, so the CR arms are bare by construction.
        for planted in (b"\r", b"\r\r\n", b"\x1b", b"\x07", " ".encode("utf-8"),
                        "​".encode("utf-8")):
            with self.subTest(planted=planted):
                payload, mutated = self.planted_render(spec, planted)
                self.assertNotEqual(payload, clean)
                self.assertIn(PLANT_MARKER, payload)
                self.assertNotIn(PLANT_MARKER, clean)
                self.assertIn(planted, mutated)
                with self.assertRaises(ScreenRefused) as raised:
                    checked(payload, f"first-use screen for {PLANT_INTO}")
                self.assertIn("unsafe terminal controls", str(raised.exception))

    def test_a_planted_crlf_is_normalised_rather_than_refused(self) -> None:
        """The other side of OD-BT, so neither direction can regress silently.

        A CRLF planted into a *different* record reaches the screen as an LF:
        the asset stays installable, the marker after it is still displayed,
        and no CR is written.
        """
        spec = self.spec_for(PLANT_INTO)
        payload, mutated = self.planted_render(spec, b"\r\n")
        self.assertIn(b"\r\n", mutated)
        self.assertNotIn(b"\r", payload)
        self.assertIn(b"\n" + PLANT_MARKER, payload)
        self.assertIs(checked(payload, f"first-use screen for {PLANT_INTO}"), payload)

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
