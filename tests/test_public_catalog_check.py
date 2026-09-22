"""The public catalog-digest check, and the cross-repository contract (OD-BP).

Nothing on the asset/v3 production path used to verify `catalog/plebian.json`
against `_CATALOG_SHA256`: the comparison existed only as the private
`receipt._verify_frozen_schema`, called by this suite. kilix's migrated
consumer therefore reached across the repository boundary for that underscore
name, fail-closed -- and a rename here would have turned its verification into
a hard refusal at install time, in a component pinned by gitlink.

These tests pin the contract from the consumer's side: the public name it
looks up first, the private name it falls back to, the refusal it makes when
it finds neither, and the fact that the check can actually fail.
"""

from __future__ import annotations

import io
import json
import unittest
from unittest import mock

import kilix_content
from kilix_content import receipt

# The exact resolution order kilix's config/content_models.py uses. Copied as
# data, not imported: kilix is a different repository and is not on this path.
CONSUMER_PUBLIC_NAME = "verified_packaged_catalog"
CONSUMER_PRIVATE_NAME = "_verify_frozen_schema"


def consumer_resolution(api: object, receipt_module: object) -> str:
    """kilix's `_verified_catalog` chain, as a name rather than a call.

    public -> private -> refuse. Written here so a rename in this repository
    fails this test rather than the consumer's install.
    """
    if callable(getattr(api, CONSUMER_PUBLIC_NAME, None)):
        return CONSUMER_PUBLIC_NAME
    if callable(getattr(receipt_module, CONSUMER_PRIVATE_NAME, None)):
        return CONSUMER_PRIVATE_NAME
    return "refused"



def _tampered_catalog(pinned: bytes) -> tuple[bytes, str, str]:
    """Catalog bytes that differ from the pins and still parse cleanly.

    One free-form description is replaced by a same-shaped marker, so the
    tamper is invisible to the parser and obvious to an assertion.
    """
    text = pinned.decode("utf-8")
    entry = json.loads(text)["content"][0]
    original = entry["description"]
    needle = json.dumps(original)
    if text.count(needle) != 1:
        raise AssertionError(f"tamper needle is not unique: {needle!r}")
    marker = "TAMPERED" + "-" * max(0, len(original) - 8)
    tampered = text.replace(needle, json.dumps(marker)).encode("utf-8")
    if tampered == pinned:
        raise AssertionError("the tamper changed nothing")
    return tampered, marker, entry["id"]


class _TamperedResource:
    """Stands in for importlib.resources' traversable, serving tampered text."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def joinpath(self, _name: str) -> "_TamperedResource":
        return self

    def open(self, mode: str = "r", encoding: str | None = None):
        if "b" in mode:
            return io.BytesIO(self._payload)
        return io.StringIO(self._payload.decode(encoding or "utf-8"))

    def read_bytes(self) -> bytes:
        return self._payload


def _tampered_resource_stream(payload: bytes):
    """Make every resource read of the packaged catalog see `payload`."""
    return mock.patch.object(
        kilix_content, "files", return_value=_TamperedResource(payload)
    )


class PublicCatalogCheckTests(unittest.TestCase):
    def test_the_consumer_resolves_to_the_public_name(self) -> None:
        self.assertEqual(
            consumer_resolution(kilix_content, receipt), CONSUMER_PUBLIC_NAME
        )

    def test_the_resolver_can_report_every_outcome(self) -> None:
        """Control: the resolver is not a function that always says 'public'."""

        class OnlyPrivate:
            pass

        class Nothing:
            pass

        only_private = OnlyPrivate()
        setattr(only_private, CONSUMER_PRIVATE_NAME, lambda: None)
        self.assertEqual(
            consumer_resolution(Nothing(), only_private), CONSUMER_PRIVATE_NAME
        )
        self.assertEqual(consumer_resolution(Nothing(), Nothing()), "refused")

    def test_the_private_name_is_the_public_function_itself(self) -> None:
        """Not a copy: one object, so the two names cannot drift apart."""
        self.assertIs(receipt._verify_frozen_schema, receipt.verify_packaged_catalog)

    def test_the_public_entry_point_returns_the_packaged_catalog(self) -> None:
        catalog = kilix_content.verified_packaged_catalog()
        # Equal to the unverified parse, and deliberately NOT the same object:
        # sharing `default_catalog()`'s cache is what let a parse pre-date its
        # own check (F2). `assertIs` here used to *depend* on that sharing.
        unverified = kilix_content.default_catalog()
        self.assertIsNot(catalog, unverified)
        self.assertEqual(
            [entry.content_id for entry in catalog],
            [entry.content_id for entry in unverified],
        )
        self.assertEqual(
            [asset.asset_id for asset in catalog.assets],
            [asset.asset_id for asset in unverified.assets],
        )
        self.assertIn("verified_packaged_catalog", kilix_content.__all__)
        self.assertIn("verify_packaged_catalog", kilix_content.__all__)
        self.assertIn("verified_catalog_bytes", kilix_content.__all__)

    def test_the_entry_point_verifies_before_it_parses(self) -> None:
        """A failing check must stop the parse, not merely precede it."""
        # Patched where `verified_packaged_catalog` looks it up: `__init__`
        # binds the name at import, so patching `receipt` would not reach it.
        with mock.patch.object(
            kilix_content, "verified_catalog_bytes",
            side_effect=RuntimeError("planted"),
        ), mock.patch.object(kilix_content.Catalog, "loads") as parse:
            with self.assertRaises(RuntimeError):
                kilix_content.verified_packaged_catalog()
        parse.assert_not_called()

    def test_the_entry_point_parses_the_bytes_it_verified(self) -> None:
        """One read, and the parser is handed exactly what the check ran over.

        The old shape verified one read of `plebian.json` and parsed a second,
        through `default_catalog()`. Two reads is the defect: the bytes that
        were checked and the bytes that were parsed were never the same object,
        so a tamper between them was verified and not parsed, parsed and not
        verified (C-V3-EXTEND-VERIFY F2 / C-MIGRATE-KILIX-VERIFY V4).
        """
        reads: list[str] = []
        real = receipt._resource_bytes

        def counted(name: str) -> bytes:
            reads.append(name)
            return real(name)

        with mock.patch.object(receipt, "_resource_bytes", counted), \
                mock.patch.object(kilix_content, "default_catalog") as cached:
            catalog = kilix_content.verified_packaged_catalog()
        cached.assert_not_called()
        self.assertEqual(reads.count(receipt._CATALOG_RESOURCE), 1, reads)
        expected = kilix_content.Catalog.loads(
            receipt.verified_catalog_bytes().decode("utf-8"),
            label="packaged catalog",
        )
        self.assertEqual(
            [entry.content_id for entry in catalog],
            [entry.content_id for entry in expected],
        )

    def test_a_tamper_landing_between_the_check_and_the_parse_is_refused(self) -> None:
        """ATTACK A, made a test: serve pinned bytes once, tampered after.

        With two reads the check sees the pinned bytes and the parser sees the
        tampered ones, and the entry point returns a tampered catalog without
        raising -- demonstrated twice by the verifier. With one read the second
        value is never asked for and the pinned content comes back.
        """
        pinned = receipt.catalog_bytes()
        tampered, marker, content_id = _tampered_catalog(pinned)
        served: list[bytes] = []
        real = receipt._resource_bytes

        def pinned_once(name: str) -> bytes:
            if name != receipt._CATALOG_RESOURCE:
                return real(name)
            payload = pinned if not served else tampered
            served.append(payload)
            return payload

        with mock.patch.object(receipt, "_resource_bytes", pinned_once), \
                _tampered_resource_stream(tampered):
            kilix_content.default_catalog.cache_clear()
            self.addCleanup(kilix_content.default_catalog.cache_clear)
            catalog = kilix_content.verified_packaged_catalog()
        self.assertNotEqual(catalog.require(content_id).description, marker)
        self.assertEqual(
            catalog.require(content_id).description,
            json.loads(pinned.decode("utf-8"))["content"][0]["description"],
        )
        self.assertEqual(len(served), 1, served)

    def test_a_poisoned_cache_cannot_reach_the_verified_entry_point(self) -> None:
        """ATTACK B, made a test: no race, no timing -- only call order.

        `default_catalog()` is `lru_cache`d and documented as the unverified
        parse, and kilix calls it directly in six places. A caller that parses
        a tampered file first leaves a bad `Catalog` in that cache; the entry
        point used to return it, having verified the pinned bytes now back on
        disk. The cache is still poisoned after the call below -- which is what
        proves the entry point did not consult it.
        """
        pinned = receipt.catalog_bytes()
        tampered, marker, content_id = _tampered_catalog(pinned)
        kilix_content.default_catalog.cache_clear()
        self.addCleanup(kilix_content.default_catalog.cache_clear)
        with _tampered_resource_stream(tampered):
            poisoned = kilix_content.default_catalog()
        self.assertEqual(poisoned.require(content_id).description, marker)

        catalog = kilix_content.verified_packaged_catalog()
        self.assertNotEqual(catalog.require(content_id).description, marker)
        self.assertIs(kilix_content.default_catalog(), poisoned)

    def test_a_moved_catalog_byte_is_refused(self) -> None:
        """The check can fail: it is not a function that always returns None."""
        with mock.patch.object(
            receipt, "catalog_bytes", return_value=b'{"schema_version": 4}'
        ):
            with self.assertRaises(RuntimeError) as raised:
                receipt.verify_packaged_catalog()
        self.assertIn("_CATALOG_SHA256", str(raised.exception))
        with mock.patch.object(
            receipt, "catalog_bytes", return_value=b'{"schema_version": 4}'
        ):
            with self.assertRaises(RuntimeError) as raised:
                receipt.verified_catalog_bytes()
        self.assertIn("_CATALOG_SHA256", str(raised.exception))
        with mock.patch.object(
            receipt, "asset_v3_schema_bytes", return_value=b"not the schema"
        ):
            with self.assertRaises(RuntimeError) as raised:
                receipt.verify_packaged_catalog()
        self.assertIn("frozen digest", str(raised.exception))
        # And on the real bytes it passes, so the two refusals above are about
        # the plant and not about a tree that cannot verify at all.
        self.assertIsNone(receipt.verify_packaged_catalog())

    def test_default_catalog_still_does_not_verify(self) -> None:
        """Stated, not assumed: the unverified parse is still available.

        A consumer that calls `default_catalog()` gets no digest check. That is
        why the public entry point exists and why the consumer must call it.
        """
        kilix_content.default_catalog.cache_clear()
        self.addCleanup(kilix_content.default_catalog.cache_clear)
        with mock.patch.object(kilix_content, "verify_packaged_catalog") as check:
            kilix_content.default_catalog()
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
