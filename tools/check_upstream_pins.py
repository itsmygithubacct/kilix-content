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


def _head_length(opener, url: str) -> int:
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "kilix-content-pin-check/0.4"}
    )
    with opener.open(request, timeout=30) as response:
        return int(response.headers.get("Content-Length", "0"))


def main() -> int:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    status = 0
    for asset in catalog.get("assets", []):
        source = asset.get("source") or {}
        mode = source.get("mode")
        if mode == "upstream-archive":
            url = source.get("url")
            expected = source.get("archive_bytes")
            if not url or expected is None:
                continue
            length = _head_length(opener, url)
            print(f"{asset['id']} Content-Length={length} pin={expected}")
            if length != expected:
                status = 1
            continue
        if mode == "upstream-files":
            by_path = {item["path"]: item for item in asset.get("files") or []}
            for item in source.get("fetch") or []:
                listed = by_path[item["path"]]
                length = _head_length(opener, item["url"])
                print(
                    f"{asset['id']} {item['path']} Content-Length={length} pin={listed['bytes']}"
                )
                if length != listed["bytes"]:
                    status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
