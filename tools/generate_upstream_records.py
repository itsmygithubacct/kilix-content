#!/usr/bin/env python3
"""Generate packaged asset/v3 records from verified upstream pins (R4-050..R4-065)."""

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
TEXTS = LICENSE_SRC / "kilix_license" / "data" / "texts"

PIN_NAMES = (
    "vosk-model-small-en-us-0.15.json",
    "vosk-model-en-us-0.22-lgraph.json",
    "qwen3-tts-0.6b-base.json",
    "qwen3-tts-0.6b-customvoice.json",
    "qwen3-tts-1.7b-voicedesign.json",
    "whisper-tiny-ggml.json",
    "piper-en-us-kristin-medium.json",
    "vibevoice-asr-bitnet.json",
    "yolox_s.json",
    "yolox_tiny.json",
    "yolox_nano.json",
    "yamnet.json",
    "bonsai-8b.json",
    "bonsai-27b.json",
    "bitnet-b1.58-2b4t.json",
    "granite4.1-3b.json",
    "nomic-embed-text-v1.5.json",
    "granite3.2-vision-2b.json",
    "qwen3.5-4b.json",
    "pocket-tts-english-q8_0.json",
    "bonsai-image-4b-ternary-gemlite.json",
    "bonsai-image-4b-binary-gemlite.json",
)

LICENSORS = {
    "small-en-us": ["Alpha Cephei Inc."],
    "lgraph-en-us": ["Appen", "Alpha Cephei"],
    "qwen3-tts-0.6b-base": ["Alibaba Cloud"],
    "qwen3-tts-0.6b-customvoice": ["Alibaba Cloud"],
    "qwen3-tts-1.7b-voicedesign": ["Alibaba Cloud"],
    "whisper-tiny-ggml": ["OpenAI"],
    "piper-en-us-kristin-medium": ["Bryce Beattie"],
    "vibevoice-asr-bitnet": ["Microsoft Corporation"],
    "yolox_s": ["Megvii (Base Detection / Megvii Inc.)"],
    "yolox_tiny": ["Megvii (Base Detection / Megvii Inc.)"],
    "yolox_nano": ["Megvii (Base Detection / Megvii Inc.)"],
    "yamnet": ["Google"],
    "bonsai-8b": ["Prism ML, Inc."],
    "bonsai-27b": ["Prism ML, Inc."],
    "bitnet-b1.58-2b4t": ["Microsoft Corporation"],
    "granite4.1:3b": ["IBM"],
    "nomic-embed-text:v1.5": ["Nomic AI"],
    "granite3.2-vision:2b": ["IBM"],
    "qwen3.5:4b": ["Alibaba Cloud / Qwen"],
    "pocket-tts-english-q8_0": ["Kyutai"],
    "bonsai-image-4b:ternary-gemlite": ["Prism ML, Inc."],
    "bonsai-image-4b:binary-gemlite": ["Prism ML, Inc."],
}

LICENSE_ROW_IDS = {
    "Apache-2.0": "apache-2.0",
    "MIT": "mit",
    "Public domain, per the trainer's statement": "public-domain",
    "CC-BY-4.0": "cc-by-4.0",
}

NOTICE_PATHS = {
    "apache-2.0": "notices/LICENSE-apache-2.0.txt",
    "mit": "notices/LICENSE-mit.txt",
    "public-domain": "notices/public-domain.txt",
    "cc-by-4.0": "notices/LICENSE-cc-by-4.0.txt",
    "llama-3-community": "notices/LICENSE-llama-3-community.txt",
}

# Component exceptions that are shown as a second licence row (OD-AB).
COMPONENT_LICENSE_ROWS = {
    "qwen2.5-1.5b-decoder-lineage": {
        "decision": "affirmative",
        "license_id": "apache-2.0",
        "licensors": ["Alibaba Cloud"],
        "notice_path": "notices/LICENSE-apache-2.0.txt",
    },
    "tokenizer-derived-from-llama-3": {
        "decision": "affirmative",
        "license_id": "llama-3-community",
        "licensors": ["Meta Platforms, Inc."],
        "notice_path": "notices/LICENSE-llama-3-community.txt",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def load_license(record_id: str):
    sys.path.insert(0, str(LICENSE_SRC))
    from kilix_license.catalog import load_determined_records

    return load_determined_records().by_id(record_id)


def license_row_id(record) -> str:
    if not record.licence_ids:
        raise SystemExit(f"{record.id} has no licence_ids")
    try:
        return LICENSE_ROW_IDS[record.licence_ids[0]]
    except KeyError as exc:
        raise SystemExit(f"{record.id} has unsupported licence {record.licence_ids[0]!r}") from exc


def notice_blob(digest: str, path: str, label: str) -> dict[str, object]:
    data = (TEXTS / digest).read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f"notice text digest mismatch for {label}")
    return {"bytes": len(data), "path": path, "sha256": digest}


def notice_file(record) -> dict[str, object]:
    return notice_blob(
        record.text_sha256, NOTICE_PATHS[license_row_id(record)], record.id
    )


def notice_files(record) -> list[dict[str, object]]:
    files = [notice_file(record)]
    for component in record.components:
        extra = COMPONENT_LICENSE_ROWS.get(component.id)
        if extra is None:
            continue
        if component.exception_text_sha256 is None:
            raise SystemExit(f"{record.id} component {component.id} has no text")
        files.append(
            notice_blob(
                component.exception_text_sha256,
                extra["notice_path"],
                f"{record.id}:{component.id}",
            )
        )
    return files


def license_rows(pin: dict, record) -> list[dict[str, object]]:
    rows = [
        {
            "decision": record.decision_class,
            "id": license_row_id(record),
            "licensors": list(LICENSORS[pin["license_record_id"]]),
            "record_digest": record.digest,
            "text_sha256": record.text_sha256,
        }
    ]
    for component in record.components:
        extra = COMPONENT_LICENSE_ROWS.get(component.id)
        if extra is None:
            continue
        if component.exception_text_sha256 is None:
            raise SystemExit(f"{record.id} component {component.id} has no text")
        rows.append(
            {
                "decision": extra["decision"],
                "id": extra["license_id"],
                "licensors": list(extra["licensors"]),
                "record_digest": record.digest,
                "text_sha256": component.exception_text_sha256,
            }
        )
    return rows


def member_files(pin: dict) -> list[dict[str, object]]:
    files = []
    for item in pin["members"]:
        files.append(
            {"bytes": item["bytes"], "path": item["path"], "sha256": item["sha256"]}
        )
    return files


def build_archive_asset(pin: dict) -> dict:
    record = load_license(pin["license_record_id"])
    files = member_files(pin)
    files.extend(notice_files(record))
    files.sort(key=lambda item: item["path"])
    installed = sum(int(item["bytes"]) for item in files)
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
        "licenses": license_rows(pin, record),
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


def build_files_asset(pin: dict) -> dict:
    record = load_license(pin["license_record_id"])
    files = member_files(pin)
    files.extend(notice_files(record))
    files.sort(key=lambda item: item["path"])
    fetch = [{"path": item["path"], "url": item["url"]} for item in pin["members"]]
    fetch.sort(key=lambda item: item["path"])
    download = sum(int(item["bytes"]) for item in pin["members"])
    installed = sum(int(item["bytes"]) for item in files)
    return {
        "compatibility": {
            "consumer_schema": pin["consumer_schema"],
            "maximum": 1,
            "minimum": 1,
        },
        "files": files,
        "id": pin["id"],
        "label": pin.get("label", pin["id"]),
        "licenses": license_rows(pin, record),
        "provider": pin["provider"],
        "schema": "kilix.content.asset/v3",
        "sizes": {
            "download_bytes": download,
            "installed_bytes": installed,
            "temporary_bytes": installed,
        },
        "source": {
            "fetch": fetch,
            "mode": "upstream-files",
            "provenance": dict(pin["provenance"]),
        },
        "stream": "F104",
        "version": pin["version"],
    }


def build_convert_asset(pin: dict) -> dict:
    record = load_license(pin["license_record_id"])
    files = member_files(pin)
    files.extend(notice_files(record))
    files.sort(key=lambda item: item["path"])
    primary = pin["input"]
    extra = [
        {"path": item["path"], "url": item["url"]}
        for item in pin["members"]
        if item["path"] != primary["path"]
    ]
    extra.sort(key=lambda item: item["path"])
    download = sum(int(item["bytes"]) for item in pin["members"])
    installed = sum(int(item["bytes"]) for item in files)
    source = {
        "conversion": {
            "argv": list(pin["conversion"]["argv"]),
            "tool_asset_id": pin["conversion"]["tool_asset_id"],
        },
        "input": {
            "bytes": primary["bytes"],
            "path": primary["path"],
            "sha256": primary["sha256"],
            "url": primary["url"],
        },
        "mode": "upstream-convert",
        "provenance": dict(pin["provenance"]),
    }
    if extra:
        source["fetch"] = extra
    return {
        "compatibility": {
            "consumer_schema": pin["consumer_schema"],
            "maximum": 1,
            "minimum": 1,
        },
        "files": files,
        "id": pin["id"],
        "label": pin.get("label", pin["id"]),
        "licenses": license_rows(pin, record),
        "provider": pin["provider"],
        "schema": "kilix.content.asset/v3",
        "sizes": {
            "download_bytes": download,
            "installed_bytes": installed,
            "temporary_bytes": download + installed,
        },
        "source": source,
        "stream": "F104",
        "version": pin["version"],
    }


def build_registry_asset(pin: dict) -> dict:
    record = load_license(pin["license_record_id"])
    files = [
        {"bytes": item["bytes"], "path": item["path"], "sha256": item["sha256"]}
        for item in pin["blobs"]
    ]
    files.extend(notice_files(record))
    files.sort(key=lambda item: item["path"])
    blobs = [{"path": item["path"], "url": item["url"]} for item in pin["blobs"]]
    blobs.sort(key=lambda item: item["path"])
    download = int(pin["manifest_bytes"])
    installed = sum(int(item["bytes"]) for item in files)
    return {
        "compatibility": {
            "consumer_schema": pin["consumer_schema"],
            "maximum": 1,
            "minimum": 1,
        },
        "files": files,
        "id": pin["id"],
        "label": pin.get("label", pin["id"]),
        "licenses": license_rows(pin, record),
        "provider": pin["provider"],
        "schema": "kilix.content.asset/v3",
        "sizes": {
            "download_bytes": download,
            "installed_bytes": installed,
            "temporary_bytes": download + installed,
        },
        "source": {
            "blobs": blobs,
            "manifest_sha256": pin["manifest_sha256"],
            "manifest_url": pin["manifest_url"],
            "mode": "registry-manifest",
            "provenance": dict(pin["provenance"]),
        },
        "stream": "F104",
        "version": pin["version"],
    }


def build_from_pin(pin: dict) -> dict:
    mode = pin.get("mode", "upstream-archive")
    if mode == "upstream-files":
        return build_files_asset(pin)
    if mode == "upstream-archive":
        return build_archive_asset(pin)
    if mode == "upstream-convert":
        return build_convert_asset(pin)
    if mode == "registry-manifest":
        return build_registry_asset(pin)
    raise SystemExit(f"unsupported pin mode {mode!r} for {pin.get('id')}")


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
        json.loads((PIN_DIR / name).read_text(encoding="utf-8")) for name in PIN_NAMES
    ]
    assets = [build_from_pin(pin) for pin in pins]
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
