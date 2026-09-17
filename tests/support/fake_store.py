"""FakeStore: ReceiptStore rooted in a temp dir, never the live store."""

from __future__ import annotations

import os
from pathlib import Path

from kilix_license.paths import refuse_live_store
from kilix_license.store import ReceiptStore


class FakeStore(ReceiptStore):
    def __init__(self, root: str | os.PathLike[str]) -> None:
        path = Path(root)
        refuse_live_store(path)
        super().__init__(path)
