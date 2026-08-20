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
    BindingMismatch,
    ReceiptError,
    ReceiptStore,
    ReleaseContext,
    UnsafeStore,
)
from kilix_content.receipt import _verify_frozen_schema


class TestReceiptStore(ReceiptStore):
    """Permit synthetic release contexts only inside the test suite."""

    __slots__ = ()

    def _require_release_authority(self, release: ReleaseContext) -> None:
        if not isinstance(release, ReleaseContext):
            raise BindingMismatch("an exact release context is required")


def open_test_store(root: str, *, clock: Any = time.time) -> ReceiptStore:
    """Open an isolated synthetic-authority store below the system temp root."""

    root_descriptor = -1
    try:
        _verify_frozen_schema()
        uid, account, _nss_home = TestReceiptStore._identity()
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
        base = TestReceiptStore._open_path(
            parent, uid, create=True, controlled_leaf=False
        )
        try:
            root_descriptor = TestReceiptStore._open_controlled_chain(
                base, (leaf,), uid
            )
        finally:
            os.close(base)
        owned_descriptor, root_descriptor = root_descriptor, -1
        store = TestReceiptStore._finish_open(
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
