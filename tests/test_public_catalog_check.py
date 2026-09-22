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
        self.assertIs(catalog, kilix_content.default_catalog())
        self.assertIn("verified_packaged_catalog", kilix_content.__all__)
        self.assertIn("verify_packaged_catalog", kilix_content.__all__)

    def test_the_entry_point_verifies_before_it_parses(self) -> None:
        """A failing check must stop the parse, not merely precede it."""
        with mock.patch.object(
            kilix_content, "verify_packaged_catalog",
            side_effect=RuntimeError("planted"),
        ), mock.patch.object(kilix_content, "default_catalog") as parse:
            with self.assertRaises(RuntimeError):
                kilix_content.verified_packaged_catalog()
        parse.assert_not_called()

    def test_a_moved_catalog_byte_is_refused(self) -> None:
        """The check can fail: it is not a function that always returns None."""
        with mock.patch.object(receipt, "catalog_sha256", return_value="f" * 64):
            with self.assertRaises(RuntimeError) as raised:
                receipt.verify_packaged_catalog()
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
