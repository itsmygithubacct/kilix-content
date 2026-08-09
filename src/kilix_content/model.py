"""Validated content-catalog model."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PREFERRED_SIZE = re.compile(r"^[1-9][0-9]{0,4}x[1-9][0-9]{0,4}$")
_HEX = frozenset("0123456789abcdef")
_SOURCE_TYPES = frozenset(("git", "archive", "system", "custom"))
_LAUNCH_MODES = frozenset(("terminal", "run", "xpane", "browse", "window", "custom"))
_ROOT_KEYS = frozenset(("schema_version", "content"))
_ENTRY_KEYS = frozenset(
    (
        "id",
        "label",
        "kind",
        "icon",
        "description",
        "source",
        "binary",
        "build",
        "dependency_hint",
        "capabilities",
        "launch",
    )
)
_LAUNCH_KEYS = frozenset(("mode", "preferred_size"))
_SOURCE_KEYS = {
    "git": frozenset(("type", "repository", "ref")),
    "archive": frozenset(("type", "urls", "sha256")),
    "system": frozenset(("type",)),
    "custom": frozenset(("type",)),
}
_MAX_CATALOG_BYTES = 1024 * 1024
_MAX_CONTENT_ENTRIES = 4096


class CatalogError(ValueError):
    """The catalog is structurally invalid or violates its trust contract."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"{label} must be an object")
    return value


def _known_keys(raw: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = tuple(key for key in raw if key not in allowed)
    if unknown:
        names = ", ".join(sorted(repr(key) for key in unknown))
        raise CatalogError(f"{label} has unknown field(s): {names}")


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"catalog JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def _valid_text(value: str) -> bool:
    if "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _exact_hex(value: str, length: int, label: str) -> str:
    if len(value) != length or not set(value) <= _HEX:
        raise CatalogError(
            f"{label} must be exactly {length} lowercase hexadecimal characters"
        )
    return value


def _relative_path(value: str, label: str) -> str:
    if not value or not _valid_text(value) or os.path.isabs(value):
        raise CatalogError(f"{label} must be a non-empty relative path")
    normalized = os.path.normpath(value)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise CatalogError(f"{label} escapes its content directory")
    return normalized


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or not _valid_text(item) for item in value
    ):
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
    def from_mapping(cls, raw: Mapping[str, Any]) -> ContentSpec:
        raw = _mapping(raw, "content entry")
        _known_keys(raw, _ENTRY_KEYS, "content entry")
        try:
            content_id = raw["id"]
            label = raw["label"]
            source = raw["source"]
        except KeyError as exc:
            raise CatalogError(f"content entry is missing {exc.args[0]!r}") from exc
        if not isinstance(content_id, str) or not _ID.fullmatch(content_id):
            raise CatalogError(f"invalid content id: {content_id!r}")
        if not isinstance(label, str) or not label.strip() or not _valid_text(label):
            raise CatalogError(f"{content_id}: label must be a non-empty string")
        source = _mapping(source, f"{content_id}.source")
        source_type = source.get("type", "")
        if not isinstance(source_type, str):
            raise CatalogError(f"{content_id}: source type must be a string")
        if source_type not in _SOURCE_TYPES:
            raise CatalogError(f"{content_id}: unsupported source type {source_type!r}")
        _known_keys(source, _SOURCE_KEYS[source_type], f"{content_id}.source")

        repository = source.get("repository", "")
        ref = source.get("ref", "")
        urls = _string_tuple(source.get("urls"), f"{content_id}.source.urls")
        sha256 = source.get("sha256", "")
        binary = raw.get("binary", "")
        if not isinstance(binary, str):
            raise CatalogError(f"{content_id}: binary must be a string")
        build = _string_tuple(raw.get("build"), f"{content_id}.build")
        launch = raw.get("launch", {})
        launch = _mapping(launch, f"{content_id}.launch")
        _known_keys(launch, _LAUNCH_KEYS, f"{content_id}.launch")
        launch_mode = launch.get("mode", "terminal")
        if not isinstance(launch_mode, str):
            raise CatalogError(f"{content_id}: launch mode must be a string")
        if launch_mode not in _LAUNCH_MODES:
            raise CatalogError(f"{content_id}: unsupported launch mode {launch_mode!r}")

        if source_type == "git":
            if (
                not isinstance(repository, str)
                or not repository
                or not _valid_text(repository)
            ):
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
            binary = _relative_path(binary, f"{content_id}.binary")
        if source_type in ("git", "archive") and not binary:
            raise CatalogError(
                f"{content_id}: installable content requires a binary path"
            )

        strings = {}
        for key in ("kind", "icon", "description", "dependency_hint"):
            value = raw.get(key, "")
            if not isinstance(value, str) or not _valid_text(value):
                raise CatalogError(f"{content_id}: {key} must be a string")
            strings[key] = value
        preferred_size = launch.get("preferred_size", "")
        if not isinstance(preferred_size, str):
            raise CatalogError(f"{content_id}: preferred_size must be a string")
        if preferred_size and not _PREFERRED_SIZE.fullmatch(preferred_size):
            raise CatalogError(
                f"{content_id}: preferred_size must use positive WIDTHxHEIGHT pixels"
            )

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
            capabilities=_string_tuple(
                raw.get("capabilities"), f"{content_id}.capabilities"
            ),
            launch_mode=launch_mode,
            preferred_size=preferred_size,
        )


class Catalog:
    """An immutable, uniquely keyed content catalog."""

    def __init__(self, entries: Iterable[ContentSpec], schema_version: int = 1):
        if type(schema_version) is not int or schema_version != 1:
            raise CatalogError(
                f"unsupported catalog schema version: {schema_version!r}"
            )
        by_id: dict[str, ContentSpec] = {}
        for entry in entries:
            if not isinstance(entry, ContentSpec):
                raise CatalogError("catalog entries must be ContentSpec instances")
            if entry.content_id in by_id:
                raise CatalogError(f"duplicate content id: {entry.content_id}")
            by_id[entry.content_id] = entry
        self.schema_version = schema_version
        self._entries = tuple(by_id.values())
        self._by_id = MappingProxyType(by_id)

    def __iter__(self) -> Iterator[ContentSpec]:
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
    def from_mapping(cls, raw: Mapping[str, Any]) -> Catalog:
        raw = _mapping(raw, "catalog root")
        _known_keys(raw, _ROOT_KEYS, "catalog root")
        entries = raw.get("content")
        if not isinstance(entries, list):
            raise CatalogError("catalog content must be an array")
        if len(entries) > _MAX_CONTENT_ENTRIES:
            raise CatalogError(
                f"catalog has more than {_MAX_CONTENT_ENTRIES} content entries"
            )
        version = raw.get("schema_version")
        if type(version) is not int:
            raise CatalogError("catalog schema_version must be an integer")
        return cls((ContentSpec.from_mapping(item) for item in entries), version)

    @classmethod
    def loads(cls, payload: str, *, label: str = "catalog") -> Catalog:
        if not isinstance(payload, str):
            raise CatalogError(f"{label} JSON must be text")
        try:
            payload_size = (
                len(payload) if payload.isascii() else len(payload.encode("utf-8"))
            )
        except UnicodeError as exc:
            raise CatalogError(f"could not parse {label}: {exc}") from exc
        if payload_size > _MAX_CATALOG_BYTES:
            raise CatalogError(f"{label} exceeds the 1 MiB size limit")
        try:
            raw = json.loads(payload, object_pairs_hook=_json_object)
        except CatalogError:
            raise
        except (json.JSONDecodeError, RecursionError) as exc:
            raise CatalogError(f"could not parse {label}: {exc}") from exc
        return cls.from_mapping(raw)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Catalog:
        try:
            with open(path, "rb") as stream:
                payload_bytes = stream.read(_MAX_CATALOG_BYTES + 1)
            if len(payload_bytes) > _MAX_CATALOG_BYTES:
                raise CatalogError(f"catalog {path} exceeds the 1 MiB size limit")
            payload = payload_bytes.decode("utf-8")
        except CatalogError:
            raise
        except (OSError, UnicodeError) as exc:
            raise CatalogError(f"could not load catalog {path}: {exc}") from exc
        return cls.loads(payload, label=f"catalog {path}")
