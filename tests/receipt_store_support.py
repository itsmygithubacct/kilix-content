"""Test-only receipt authority and secure temporary-store opener.

This module is deliberately outside ``src/`` so permissive synthetic release
authority is never installed in the runtime wheel.
"""

from __future__ import annotations

import os
import tempfile
import time
from typing import Any

from kilix_content import (
    AssetSpec,
    BindingMismatch,
    Catalog,
    CatalogError,
    ReceiptError,
    ReceiptStore,
    ReleaseContext,
    UnsafeStore,
)
from kilix_content.receipt import _verify_frozen_schema


class TestReceiptStore(ReceiptStore):
    """Permit synthetic release contexts only inside the test suite.

    Two production guarantees are relaxed here and nowhere else: the packaged
    provenance marker is not required, and catalog membership is checked
    against an injected synthetic catalog rather than the packaged one. When
    ``admitted`` is empty the membership lookup is skipped entirely so the
    pre-existing durability, concurrency, parser and conversion suites keep
    testing what they were written to test.

    Production membership and provenance are exercised against the real
    packaged catalog in ``tests/test_packaged_authority.py``. This module lives
    outside ``src/`` so none of this reaches the runtime wheel.
    """

    __slots__ = ()

    admitted: tuple[AssetSpec, ...] = ()

    def _require_release_authority(self, release: ReleaseContext) -> Catalog:
        if not isinstance(release, ReleaseContext):
            raise BindingMismatch("an exact release context is required")
        return Catalog((), 4, assets=self.admitted)

    def _require_catalog_membership(
        self, catalog: Catalog, spec: AssetSpec
    ) -> AssetSpec:
        if not isinstance(spec, AssetSpec):
            raise BindingMismatch("an exact asset record is required")
        try:
            canonical = AssetSpec.canonicalized(spec)
        except (CatalogError, AttributeError, TypeError, ValueError) as exc:
            raise BindingMismatch("asset record failed canonical validation") from exc
        if self.admitted:
            return ReceiptStore._require_catalog_membership(catalog, canonical)
        return canonical


class ClosedGateReceiptStore(TestReceiptStore):
    """Simulate step 5 reverted: every release context is refused.

    Rollback must refuse without destroying anything already recorded, so this
    reproduces the pre-step-5 gate while leaving the store otherwise intact.
    """

    __slots__ = ()

    def _require_release_authority(self, release: ReleaseContext) -> Catalog:
        del release
        raise BindingMismatch("production authorization is disabled")


def open_test_store(
    root: str,
    *,
    clock: Any = time.time,
    assets: Any = (),
    store_type: type[ReceiptStore] | None = None,
) -> ReceiptStore:
    """Open an isolated synthetic-authority store below the system temp root."""

    root_descriptor = -1
    # ``ReceiptStore`` uses ``__slots__``, so admitted records are carried by a
    # per-call subclass rather than an instance attribute.
    store_class = TestReceiptStore if store_type is None else store_type
    if assets:
        store_class = type(
            "AdmittedTestReceiptStore",
            (store_class,),
            {"__slots__": (), "admitted": tuple(assets)},
        )
    try:
        _verify_frozen_schema()
        uid, account, _nss_home = store_class._identity()
        root = os.path.abspath(os.fspath(root))
        temporary_root = os.path.realpath(tempfile.gettempdir())
        if (
            os.path.commonpath((os.path.realpath(root), temporary_root))
            != temporary_root
        ):
            raise UnsafeStore("test receipt roots must stay below the temporary root")
        parent, leaf = os.path.split(root)
        if not leaf:
            raise UnsafeStore("test receipt root needs a final path component")
        base = store_class._open_path(
            parent, uid, create=True, controlled_leaf=False
        )
        try:
            root_descriptor = store_class._open_controlled_chain(
                base, (leaf,), uid
            )
        finally:
            os.close(base)
        owned_descriptor, root_descriptor = root_descriptor, -1
        store = store_class._finish_open(
            owned_descriptor, root, uid, account, clock=clock
        )
        return store
    except ReceiptError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafeStore("could not securely open the test receipt store") from exc
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
