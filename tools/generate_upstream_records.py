#!/usr/bin/env python3
"""Generate packaged asset/v3 records from verified upstream pins (R4-050, R4-052)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_DIR = ROOT / "tools" / "upstream-pins"
CATALOG = ROOT / "src" / "kilix_content" / "catalog" / "plebian.json"
RECEIPT = ROOT / "src" / "kilix_content" / "receipt.py"
SCHEMA = ROOT / "src" / "kilix_content" / "contracts" / "kilix.content.asset-v3.schema.json"
LICENSE_SRC = ROOT / "third_party" / "kilix-license" / "src"
NOTICE_NAME = "notices/LICENSE-apache-2.0.txt"
APACHE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

LICENSORS = {
    "small-en-us": ["Alpha Cephei Inc."],
    "lgraph-en-us": ["Appen", "Alpha Cephei"],
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def load_license(record_id: str):
    sys.path.insert(0, str(LICENSE_SRC))
    from kilix_license.catalog import load_determined_records

    return load_determined_records().by_id(record_id)


def notice_bytes() -> int:
    path = LICENSE_SRC / "kilix_license" / "data" / "texts" / APACHE
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != APACHE:
        raise SystemExit("Apache-2.0 text digest mismatch")
    return len(data)


def build_asset(pin: dict, notice_size: int) -> dict:
    record = load_license(pin["license_record_id"])
    members = list(pin["members"])
    files = [
        {"bytes": item["bytes"], "path": item["path"], "sha256": item["sha256"]}
        for item in members
    ]
    files.append({"bytes": notice_size, "path": NOTICE_NAME, "sha256": APACHE})
    files.sort(key=lambda item: item["path"])
    installed = sum(item["bytes"] for item in files)
    download = pin["archive_bytes"]
    return {
        "compatibility": {
            "consumer_schema": "kilix.speech.models/v1",
            "maximum": 1,
            "minimum": 1,
        },
        "files": files,
        "id": pin["id"],
        "label": pin["id"],
        "licenses": [
            {
                "decision": record.decision_class,
                "id": "apache-2.0",
                "licensors": list(LICENSORS[pin["license_record_id"]]),
                "record_digest": record.digest,
                "text_sha256": record.text_sha256,
            }
        ],
        "provider": "kilix-voice",
        "schema": "kilix.content.asset/v3",
        "sizes": {
            "download_bytes": download,
            "installed_bytes": installed,
            "temporary_bytes": download + installed,
        },
        "source": {
            "archive_bytes": pin["archive_bytes"],
            "archive_sha256": pin["archive_sha256"],
            "format": pin["format"],
            "mode": "upstream-archive",
            "provenance": dict(pin["provenance"]),
            "root": pin["root"],
            "url": pin["archive_url"],
        },
        "stream": "F104",
        "version": pin["version"],
    }


def replace_pin(path: Path, name: str, new_sha: str, old_sha: str | None) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = rf"({name} = \(\n    \")([0-9a-f]{{64}})(\"\n\))"
    match = re.search(pattern, text)
    if match is None:
        raise SystemExit(f"could not find {name} in {path}")
    current = match.group(2)
    if current == new_sha:
        return
    if current != "0" * 64 and old_sha is not None and current != old_sha:
        raise SystemExit(
            f"{name} old-value guard failed: have {current}, expected {old_sha}"
        )
    if current != "0" * 64 and old_sha is None:
        raise SystemExit(f"{name} refuses to change {current} without --old")
    path.write_text(text[: match.start(2)] + new_sha + text[match.end(2) :], encoding="utf-8")


def render_catalog(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--old", dest="old_sha", default=None)
    args = parser.parse_args(argv[1:])
    pins = [
        json.loads((PIN_DIR / "vosk-model-small-en-us-0.15.json").read_text(encoding="utf-8")),
        json.loads((PIN_DIR / "vosk-model-en-us-0.22-lgraph.json").read_text(encoding="utf-8")),
    ]
    notice_size = notice_bytes()
    assets = [build_asset(pin, notice_size) for pin in pins]
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    catalog["schema_version"] = 4
    catalog["assets"] = assets
    rendered = render_catalog(catalog)
    if args.check:
        if CATALOG.read_text(encoding="utf-8") != rendered:
            raise SystemExit("catalog/plebian.json does not match the generator")
        return 0
    CATALOG.write_text(rendered, encoding="utf-8")
    catalog_sha = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    schema_sha = sha256_file(SCHEMA)
    replace_pin(RECEIPT, "_CATALOG_SHA256", catalog_sha, args.old_sha)
    replace_pin(RECEIPT, "_ASSET_V3_SCHEMA_SHA256", schema_sha, "0" * 64)
    print(f"catalog sha256 {catalog_sha}")
    print(f"schema sha256 {schema_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
