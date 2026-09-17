#!/usr/bin/env python3
"""Manual, read-only HEAD check of pinned upstream URLs. Never part of the suite."""

from __future__ import annotations

import json
import ssl
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "kilix_content" / "catalog" / "plebian.json"


def main() -> int:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    status = 0
    for asset in catalog.get("assets", []):
        source = asset.get("source") or {}
        url = source.get("url")
        expected = source.get("archive_bytes")
        if not url or expected is None:
            continue
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "kilix-content-pin-check/0.4"})
        with opener.open(request, timeout=30) as response:
            length = int(response.headers.get("Content-Length", "0"))
        print(f"{asset['id']} Content-Length={length} pin={expected}")
        if length != expected:
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
