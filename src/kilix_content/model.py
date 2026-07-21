"""Validated content-catalog model."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from typing import Any, Iterable, Mapping


_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX = frozenset("0123456789abcdef")
_SOURCE_TYPES = frozenset(("git", "archive", "system", "custom"))
_LAUNCH_MODES = frozenset(("terminal", "run", "xpane", "browse", "window", "custom"))


class CatalogError(ValueError):
    """The catalog is structurally invalid or violates its trust contract."""


def _exact_hex(value: str, length: int, label: str) -> str:
    if len(value) != length or any(ch not in _HEX for ch in value):
        raise CatalogError(f"{label} must be exactly {length} lowercase hexadecimal characters")
    return value


def _relative_path(value: str, label: str) -> str:
    if not value or os.path.isabs(value):
        raise CatalogError(f"{label} must be a non-empty relative path")
    normalized = os.path.normpath(value)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise CatalogError(f"{label} escapes its content directory")
    return normalized


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise CatalogError(f"{label} must be an array of non-empty strings")
    return tuple(value)


@dataclass(frozen=True)
class ContentSpec:
    content_id: str
    label: str
    kind: str
    icon: str
    description: str
    source_type: str
    repository: str = ""
    ref: str = ""
    urls: tuple[str, ...] = ()
    sha256: str = ""
    binary: str = ""
    build: tuple[str, ...] = ()
    dependency_hint: str = ""
    capabilities: tuple[str, ...] = ()
    launch_mode: str = "terminal"
    preferred_size: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ContentSpec":
        try:
            content_id = raw["id"]
            label = raw["label"]
            source = raw["source"]
        except KeyError as exc:
            raise CatalogError(f"content entry is missing {exc.args[0]!r}") from exc
        if not isinstance(content_id, str) or not _ID.fullmatch(content_id):
            raise CatalogError(f"invalid content id: {content_id!r}")
        if not isinstance(label, str) or not label.strip():
            raise CatalogError(f"{content_id}: label must be a non-empty string")
        if not isinstance(source, Mapping):
            raise CatalogError(f"{content_id}: source must be an object")
        source_type = source.get("type", "")
        if source_type not in _SOURCE_TYPES:
            raise CatalogError(f"{content_id}: unsupported source type {source_type!r}")

        repository = source.get("repository", "")
        ref = source.get("ref", "")
        urls = _string_tuple(source.get("urls"), f"{content_id}.source.urls")
        sha256 = source.get("sha256", "")
        binary = raw.get("binary", "")
        build = _string_tuple(raw.get("build"), f"{content_id}.build")
        launch = raw.get("launch", {})
        if not isinstance(launch, Mapping):
            raise CatalogError(f"{content_id}: launch must be an object")
        launch_mode = launch.get("mode", "terminal")
        if launch_mode not in _LAUNCH_MODES:
            raise CatalogError(f"{content_id}: unsupported launch mode {launch_mode!r}")

        if source_type == "git":
            if not isinstance(repository, str) or not repository:
                raise CatalogError(f"{content_id}: git repository is required")
            if not isinstance(ref, str):
                raise CatalogError(f"{content_id}: git ref must be a string")
            _exact_hex(ref, 40, f"{content_id}.source.ref")
        elif source_type == "archive":
            if not urls:
                raise CatalogError(f"{content_id}: archive URLs are required")
            if not isinstance(sha256, str):
                raise CatalogError(f"{content_id}: archive sha256 must be a string")
            _exact_hex(sha256, 64, f"{content_id}.source.sha256")

        if binary:
            if not isinstance(binary, str):
                raise CatalogError(f"{content_id}: binary must be a string")
            binary = _relative_path(binary, f"{content_id}.binary")
        if source_type in ("git", "archive") and not binary:
            raise CatalogError(f"{content_id}: installable content requires a binary path")

        strings = {}
        for key in ("kind", "icon", "description", "dependency_hint"):
            value = raw.get(key, "")
            if not isinstance(value, str):
                raise CatalogError(f"{content_id}: {key} must be a string")
            strings[key] = value
        preferred_size = launch.get("preferred_size", "")
        if not isinstance(preferred_size, str):
            raise CatalogError(f"{content_id}: preferred_size must be a string")

        return cls(
            content_id=content_id,
            label=label.strip(),
            kind=strings["kind"] or "game",
            icon=strings["icon"],
            description=strings["description"],
            source_type=source_type,
            repository=repository,
            ref=ref,
            urls=urls,
            sha256=sha256,
            binary=binary,
            build=build,
            dependency_hint=strings["dependency_hint"],
            capabilities=_string_tuple(raw.get("capabilities"), f"{content_id}.capabilities"),
            launch_mode=launch_mode,
            preferred_size=preferred_size,
        )


class Catalog:
    """An immutable, uniquely keyed content catalog."""

    def __init__(self, entries: Iterable[ContentSpec], schema_version: int = 1):
        if schema_version != 1:
            raise CatalogError(f"unsupported catalog schema version: {schema_version!r}")
        by_id: dict[str, ContentSpec] = {}
        for entry in entries:
            if entry.content_id in by_id:
                raise CatalogError(f"duplicate content id: {entry.content_id}")
            by_id[entry.content_id] = entry
        self.schema_version = schema_version
        self._entries = tuple(by_id.values())
        self._by_id = by_id

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, content_id: str) -> ContentSpec | None:
        return self._by_id.get(content_id)

    def require(self, content_id: str) -> ContentSpec:
        try:
            return self._by_id[content_id]
        except KeyError as exc:
            raise CatalogError(f"unknown content id: {content_id}") from exc

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "Catalog":
        if not isinstance(raw, Mapping):
            raise CatalogError("catalog root must be an object")
        entries = raw.get("content")
        if not isinstance(entries, list):
            raise CatalogError("catalog content must be an array")
        version = raw.get("schema_version")
        if not isinstance(version, int):
            raise CatalogError("catalog schema_version must be an integer")
        return cls((ContentSpec.from_mapping(item) for item in entries), version)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Catalog":
        try:
            with open(path, encoding="utf-8") as stream:
                raw = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"could not load catalog {path}: {exc}") from exc
        return cls.from_mapping(raw)

