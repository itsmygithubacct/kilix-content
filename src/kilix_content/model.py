"""Validated content-catalog model."""

from __future__ import annotations

import json
import os
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PREFERRED_SIZE = re.compile(r"^[1-9][0-9]{0,4}x[1-9][0-9]{0,4}$")
_HEX = frozenset("0123456789abcdef")
_SOURCE_TYPES = frozenset(("git", "archive", "system", "custom"))
_INSTALLABLE_SOURCE_TYPES = frozenset(("git", "archive"))
_LAUNCH_MODES = frozenset(("terminal", "run", "xpane", "browse", "window", "custom"))
_SCHEMA_VERSIONS = frozenset((1, 2, 3, 4))
_ROOT_KEYS = frozenset(("schema_version", "packages", "content", "assets"))
_PACKAGE_KEYS = frozenset(("id", "source", "build", "dependency_hint"))
_ENTRY_KEYS = frozenset(
    (
        "id",
        "label",
        "kind",
        "icon",
        "description",
        "source",
        "package",
        "binary",
        "command",
        "build",
        "dependency_hint",
        "capabilities",
        "actions",
        "accepts",
        "lifecycle",
        "launch",
    )
)
_LAUNCH_KEYS = frozenset(("mode", "preferred_size"))
_ACTION_KEYS = frozenset(("argv", "accepts_input", "description"))
_LIFECYCLE_KEYS = frozenset(
    (
        "single_instance",
        "requires_kilix_session",
        "degrades_inplace",
        "preserve_on_failure",
        "startup_timeout_seconds",
    )
)
_SCHEMA_THREE_ENTRY_KEYS = frozenset(
    ("command", "actions", "accepts", "lifecycle")
)
_SOURCE_KEYS = {
    "git": frozenset(("type", "repository", "ref")),
    "archive": frozenset(("type", "urls", "sha256")),
    "system": frozenset(("type",)),
    "custom": frozenset(("type",)),
}
_MAX_CATALOG_BYTES = 1024 * 1024
_MAX_CONTENT_ENTRIES = 4096
_MAX_ACTIONS = 64
_MAX_ACCEPTED_INPUTS = 64
_MAX_ASSETS = 4096
_MAX_ASSET_FILES = 100000
_MAX_SEQUENCE_ITEMS = 256
_MAX_TEXT_LENGTH = 4096
_MAX_CATALOG_DEPTH = 64


class CatalogError(ValueError):
    """The catalog is structurally invalid or violates its trust contract."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"{label} must be an object")
    return value


def _known_keys(raw: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = tuple(key for key in raw if key not in allowed)
    if unknown:
        raise CatalogError(f"{label} has unknown field(s)")


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("catalog JSON contains a duplicate field")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token.removeprefix("-")) > 20:
        raise CatalogError("catalog JSON integer exceeds the numeric limit")
    try:
        return int(token)
    except ValueError as exc:
        raise CatalogError("catalog JSON integer is invalid") from exc


def _reject_json_number(_token: str) -> float:
    raise CatalogError("catalog JSON floating-point values are unsupported")


def _catalog_json_size(value: Any, *, depth: int = 0) -> int:
    """Return compact UTF-8 JSON size for a direct mapping, within hard bounds."""

    if depth > _MAX_CATALOG_DEPTH:
        raise CatalogError("catalog mapping exceeds the nesting limit")
    if isinstance(value, Mapping):
        total = 2
        for index, (key, item) in enumerate(value.items()):
            if not isinstance(key, str):
                raise CatalogError("catalog mapping field names must be strings")
            try:
                key_bytes = json.dumps(key, ensure_ascii=False).encode("utf-8")
            except (TypeError, UnicodeError, ValueError) as exc:
                raise CatalogError("catalog mapping has an invalid field name") from exc
            total += (1 if index else 0) + len(key_bytes) + 1
            total += _catalog_json_size(item, depth=depth + 1)
            if total > _MAX_CATALOG_BYTES:
                raise CatalogError("catalog mapping exceeds the 1 MiB size limit")
        return total
    if isinstance(value, list):
        total = 2
        for index, item in enumerate(value):
            total += (1 if index else 0) + _catalog_json_size(
                item, depth=depth + 1
            )
            if total > _MAX_CATALOG_BYTES:
                raise CatalogError("catalog mapping exceeds the 1 MiB size limit")
        return total
    if isinstance(value, str):
        try:
            size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        except (TypeError, UnicodeError, ValueError) as exc:
            raise CatalogError("catalog mapping contains invalid text") from exc
    elif value is None:
        size = 4
    elif type(value) is bool:
        size = 4 if value else 5
    elif type(value) is int:
        if value.bit_length() > 67:
            raise CatalogError("catalog mapping integer exceeds the numeric limit")
        token = str(value)
        if len(token.removeprefix("-")) > 20:
            raise CatalogError("catalog mapping integer exceeds the numeric limit")
        size = len(token)
    else:
        raise CatalogError("catalog mapping contains a non-JSON value")
    if size > _MAX_CATALOG_BYTES:
        raise CatalogError("catalog mapping exceeds the 1 MiB size limit")
    return size


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
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT_LENGTH
        or not _valid_text(value)
        or os.path.isabs(value)
    ):
        raise CatalogError(f"{label} must be a non-empty relative path")
    normalized = os.path.normpath(value)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise CatalogError(f"{label} escapes its content directory")
    return normalized


def _asset_relative_path(value: str, label: str) -> str:
    """Return one canonical POSIX asset path without normalization aliases."""
    value = _nonempty_text(value, label)
    parts = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise CatalogError(f"{label} must be a canonical relative POSIX path")
    return value


def _string_tuple(
    value: Any,
    label: str,
    *,
    maximum: int = _MAX_SEQUENCE_ITEMS,
    unique: bool = False,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > maximum:
        raise CatalogError(
            f"{label} must be an array of at most {maximum} non-empty strings"
        )
    result = tuple(
        _nonempty_text(item, f"{label} item", maximum=_MAX_TEXT_LENGTH)
        for item in value
    )
    if unique and len(result) != len(set(result)):
        raise CatalogError(f"{label} must not contain duplicates")
    return result


def _content_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise CatalogError(f"invalid {label}: {value!r}")
    return value


def _nonempty_text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not _valid_text(value)
    ):
        raise CatalogError(f"{label} must be a non-empty string")
    return value


def _diagnostic_identifier(value: Any, label: str, *, maximum: int = 128) -> str:
    value = _nonempty_text(value, label, maximum=maximum)
    if any(unicodedata.category(character) in ("Cc", "Cf", "Zl", "Zp") for character in value):
        raise CatalogError(f"{label} contains control or formatting characters")
    return value


def _byte_count(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise CatalogError(f"{label} must be a non-negative 64-bit integer")
    return value


def _https_url(value: Any, label: str) -> str:
    value = _nonempty_text(value, label)
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise CatalogError(f"{label} contains whitespace or control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CatalogError(f"{label} has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
        or parsed.query
        or parsed.fragment
    ):
        raise CatalogError(f"{label} must be a public HTTPS URL")
    return value


@dataclass(frozen=True)
class AssetFileSpec:
    """One immutable regular file in an asset manifest."""

    path: str
    bytes: int
    sha256: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], label: str) -> AssetFileSpec:
        raw = _mapping(raw, label)
        _known_keys(raw, frozenset(("path", "bytes", "sha256")), label)
        try:
            path = _asset_relative_path(raw["path"], f"{label}.path")
            size = _byte_count(raw["bytes"], f"{label}.bytes")
            digest = raw["sha256"]
        except KeyError as exc:
            raise CatalogError(f"{label} is missing {exc.args[0]!r}") from exc
        if not isinstance(digest, str):
            raise CatalogError(f"{label}.sha256 must be a string")
        return cls(path, size, _exact_hex(digest, 64, f"{label}.sha256"))


@dataclass(frozen=True)
class AssetLicenseSpec:
    """Exact license text and required decision class for an asset."""

    license_id: str
    text_sha256: str
    decision: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], label: str) -> AssetLicenseSpec:
        raw = _mapping(raw, label)
        _known_keys(raw, frozenset(("id", "text_sha256", "decision")), label)
        try:
            license_id = _diagnostic_identifier(
                raw["id"], f"{label}.id", maximum=128
            )
            digest = raw["text_sha256"]
            decision = raw["decision"]
        except KeyError as exc:
            raise CatalogError(f"{label} is missing {exc.args[0]!r}") from exc
        if not isinstance(digest, str):
            raise CatalogError(f"{label}.text_sha256 must be a string")
        if decision not in ("informational", "affirmative", "user-supplied"):
            raise CatalogError(f"{label}.decision is unsupported")
        return cls(
            license_id,
            _exact_hex(digest, 64, f"{label}.text_sha256"),
            decision,
        )


@dataclass(frozen=True)
class AssetSpec:
    """A validated immutable non-executable asset record."""

    asset_id: str
    label: str
    provider: str
    stream: str
    version: str
    files: tuple[AssetFileSpec, ...]
    source_mode: str
    mirrors: tuple[str, ...]
    official_url: str
    archive_sha256: str
    input_bytes: int
    input_sha256: str
    reason: str
    conversion_tool_asset_id: str
    conversion_argv: tuple[str, ...]
    provenance_project: str
    provenance_revision: str
    provenance_url: str
    download_bytes: int
    installed_bytes: int
    temporary_bytes: int
    licenses: tuple[AssetLicenseSpec, ...]
    consumer_schema: str
    compatibility_minimum: int
    compatibility_maximum: int

    def to_mapping(self) -> dict[str, Any]:
        """Return the canonical language-neutral asset record mapping."""
        provenance = {
            "original_url": self.provenance_url,
            "project": self.provenance_project,
            "revision": self.provenance_revision,
        }
        if self.source_mode == "mirrored":
            source: dict[str, Any] = {
                "archive_sha256": self.archive_sha256,
                "mirrors": list(self.mirrors),
                "mode": "mirrored",
                "provenance": provenance,
            }
        else:
            source = {
                "input_bytes": self.input_bytes,
                "input_sha256": self.input_sha256,
                "mode": self.source_mode,
                "official_url": self.official_url,
                "provenance": provenance,
                "reason": self.reason,
            }
            if self.conversion_argv:
                source["conversion"] = {
                    "argv": list(self.conversion_argv),
                    "tool_asset_id": self.conversion_tool_asset_id,
                }
        return {
            "compatibility": {
                "consumer_schema": self.consumer_schema,
                "maximum": self.compatibility_maximum,
                "minimum": self.compatibility_minimum,
            },
            "files": [
                {"bytes": item.bytes, "path": item.path, "sha256": item.sha256}
                for item in self.files
            ],
            "id": self.asset_id,
            "label": self.label,
            "licenses": [
                {
                    "decision": item.decision,
                    "id": item.license_id,
                    "text_sha256": item.text_sha256,
                }
                for item in self.licenses
            ],
            "provider": self.provider,
            "schema": "kilix.content.asset/v1",
            "sizes": {
                "download_bytes": self.download_bytes,
                "installed_bytes": self.installed_bytes,
                "temporary_bytes": self.temporary_bytes,
            },
            "source": source,
            "stream": self.stream,
            "version": self.version,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AssetSpec:
        raw = _mapping(raw, "asset entry")
        _known_keys(
            raw,
            frozenset(
                (
                    "schema", "id", "label", "provider", "stream", "version",
                    "files", "source", "sizes", "licenses", "compatibility",
                )
            ),
            "asset entry",
        )
        required = (
            "schema", "id", "label", "provider", "stream", "version", "files",
            "source", "sizes", "licenses", "compatibility",
        )
        missing = next((key for key in required if key not in raw), None)
        if missing is not None:
            raise CatalogError(f"asset entry is missing {missing!r}")
        if raw["schema"] != "kilix.content.asset/v1":
            raise CatalogError("asset entry has unsupported schema")
        asset_id = _content_id(raw["id"], "asset id")
        label = _nonempty_text(raw["label"], f"{asset_id}.label", maximum=256)
        provider = _content_id(raw["provider"], f"{asset_id}.provider")
        stream = raw["stream"]
        if not isinstance(stream, str) or not re.fullmatch(r"F[0-9]{3}", stream):
            raise CatalogError(f"{asset_id}.stream must be an FNNN identifier")
        version = _nonempty_text(raw["version"], f"{asset_id}.version", maximum=128)

        raw_files = raw["files"]
        if not isinstance(raw_files, list) or not raw_files:
            raise CatalogError(f"{asset_id}.files must be a non-empty array")
        if len(raw_files) > _MAX_ASSET_FILES:
            raise CatalogError(f"{asset_id}.files exceeds {_MAX_ASSET_FILES} entries")
        files = tuple(
            AssetFileSpec.from_mapping(item, f"{asset_id}.files[{index}]")
            for index, item in enumerate(raw_files)
        )
        paths = tuple(item.path for item in files)
        if len(paths) != len(set(paths)):
            raise CatalogError(f"{asset_id}.files contains duplicate paths")

        sizes = _mapping(raw["sizes"], f"{asset_id}.sizes")
        _known_keys(
            sizes,
            frozenset(("download_bytes", "installed_bytes", "temporary_bytes")),
            f"{asset_id}.sizes",
        )
        try:
            download_bytes = _byte_count(sizes["download_bytes"], f"{asset_id}.sizes.download_bytes")
            installed_bytes = _byte_count(sizes["installed_bytes"], f"{asset_id}.sizes.installed_bytes")
            temporary_bytes = _byte_count(sizes["temporary_bytes"], f"{asset_id}.sizes.temporary_bytes")
        except KeyError as exc:
            raise CatalogError(f"{asset_id}.sizes is missing {exc.args[0]!r}") from exc
        if installed_bytes != sum(item.bytes for item in files):
            raise CatalogError(f"{asset_id}.sizes.installed_bytes does not match files")

        raw_licenses = raw["licenses"]
        if not isinstance(raw_licenses, list) or not raw_licenses:
            raise CatalogError(f"{asset_id}.licenses must be a non-empty array")
        licenses = tuple(
            AssetLicenseSpec.from_mapping(item, f"{asset_id}.licenses[{index}]")
            for index, item in enumerate(raw_licenses)
        )
        license_ids = tuple(item.license_id for item in licenses)
        if len(license_ids) != len(set(license_ids)):
            raise CatalogError(
                f"{asset_id}.licenses contains a duplicate license id"
            )

        compatibility = _mapping(raw["compatibility"], f"{asset_id}.compatibility")
        _known_keys(
            compatibility,
            frozenset(("consumer_schema", "minimum", "maximum")),
            f"{asset_id}.compatibility",
        )
        try:
            consumer_schema = _nonempty_text(
                compatibility["consumer_schema"],
                f"{asset_id}.compatibility.consumer_schema",
                maximum=128,
            )
            compatibility_minimum = compatibility["minimum"]
            compatibility_maximum = compatibility["maximum"]
        except KeyError as exc:
            raise CatalogError(f"{asset_id}.compatibility is missing {exc.args[0]!r}") from exc
        if (
            type(compatibility_minimum) is not int
            or type(compatibility_maximum) is not int
            or compatibility_minimum < 1
            or compatibility_minimum > compatibility_maximum
        ):
            raise CatalogError(f"{asset_id}.compatibility range is invalid")

        source = _mapping(raw["source"], f"{asset_id}.source")
        source_mode = source.get("mode")
        mirrors: tuple[str, ...] = ()
        official_url = archive_sha256 = input_sha256 = reason = ""
        input_bytes = 0
        conversion_tool_asset_id = ""
        conversion_argv: tuple[str, ...] = ()
        if source_mode == "mirrored":
            _known_keys(source, frozenset(("mode", "mirrors", "archive_sha256", "provenance")), f"{asset_id}.source")
            mirrors = _string_tuple(
                source.get("mirrors"),
                f"{asset_id}.source.mirrors",
                unique=True,
            )
            if not mirrors:
                raise CatalogError(f"{asset_id}.source.mirrors must not be empty")
            mirrors = tuple(_https_url(url, f"{asset_id}.source.mirrors") for url in mirrors)
            digest = source.get("archive_sha256")
            if not isinstance(digest, str):
                raise CatalogError(f"{asset_id}.source.archive_sha256 must be a string")
            archive_sha256 = _exact_hex(digest, 64, f"{asset_id}.source.archive_sha256")
        elif source_mode == "user-supplied":
            _known_keys(source, frozenset(("mode", "official_url", "reason", "input_bytes", "input_sha256", "conversion", "provenance")), f"{asset_id}.source")
            official_url = _https_url(source.get("official_url"), f"{asset_id}.source.official_url")
            reason = _nonempty_text(source.get("reason"), f"{asset_id}.source.reason", maximum=2048)
            input_bytes = _byte_count(source.get("input_bytes"), f"{asset_id}.source.input_bytes")
            digest = source.get("input_sha256")
            if not isinstance(digest, str):
                raise CatalogError(f"{asset_id}.source.input_sha256 must be a string")
            input_sha256 = _exact_hex(digest, 64, f"{asset_id}.source.input_sha256")
            if not any(item.decision == "user-supplied" for item in licenses):
                raise CatalogError(f"{asset_id}: user-supplied source requires a user-supplied license decision")
            conversion = source.get("conversion")
            if conversion is not None:
                conversion = _mapping(conversion, f"{asset_id}.source.conversion")
                _known_keys(conversion, frozenset(("tool_asset_id", "argv")), f"{asset_id}.source.conversion")
                conversion_tool_asset_id = _content_id(conversion.get("tool_asset_id"), "conversion tool asset id")
                conversion_argv = _string_tuple(
                    conversion.get("argv"),
                    f"{asset_id}.source.conversion.argv",
                    maximum=256,
                )
                if conversion_argv.count("{input}") != 1 or conversion_argv.count("{output}") != 1:
                    raise CatalogError(f"{asset_id}.source.conversion.argv requires one {{input}} and one {{output}}")
                if any(
                    ("{" in argument or "}" in argument)
                    and argument not in ("{input}", "{output}")
                    for argument in conversion_argv
                ):
                    raise CatalogError(
                        f"{asset_id}.source.conversion.argv placeholders must be whole arguments"
                    )
        else:
            raise CatalogError(f"{asset_id}.source has unsupported mode {source_mode!r}")

        provenance = _mapping(source.get("provenance"), f"{asset_id}.source.provenance")
        _known_keys(provenance, frozenset(("project", "revision", "original_url")), f"{asset_id}.source.provenance")
        provenance_project = _nonempty_text(provenance.get("project"), f"{asset_id}.source.provenance.project", maximum=256)
        provenance_revision = _nonempty_text(provenance.get("revision"), f"{asset_id}.source.provenance.revision", maximum=256)
        provenance_url = _https_url(provenance.get("original_url"), f"{asset_id}.source.provenance.original_url")

        return cls(
            asset_id, label, provider, stream, version, files, source_mode,
            mirrors, official_url, archive_sha256, input_bytes, input_sha256,
            reason, conversion_tool_asset_id, conversion_argv,
            provenance_project, provenance_revision, provenance_url,
            download_bytes, installed_bytes, temporary_bytes, licenses,
            consumer_schema, compatibility_minimum, compatibility_maximum,
        )


def _source_fields(
    value: Any, label: str
) -> tuple[str, str, str, tuple[str, ...], str]:
    source = _mapping(value, label)
    source_type = source.get("type", "")
    if not isinstance(source_type, str):
        raise CatalogError(f"{label} type must be a string")
    if source_type not in _SOURCE_TYPES:
        raise CatalogError(f"{label} has unsupported type {source_type!r}")
    _known_keys(source, _SOURCE_KEYS[source_type], label)

    repository = source.get("repository", "")
    ref = source.get("ref", "")
    urls = _string_tuple(source.get("urls"), f"{label}.urls", unique=True)
    sha256 = source.get("sha256", "")
    if source_type == "git":
        if (
            not isinstance(repository, str)
            or not repository
            or len(repository) > _MAX_TEXT_LENGTH
            or not _valid_text(repository)
        ):
            raise CatalogError(f"{label} git repository is required")
        if not isinstance(ref, str):
            raise CatalogError(f"{label} git ref must be a string")
        _exact_hex(ref, 40, f"{label}.ref")
    elif source_type == "archive":
        if not urls:
            raise CatalogError(f"{label} archive URLs are required")
        if not isinstance(sha256, str):
            raise CatalogError(f"{label} archive sha256 must be a string")
        _exact_hex(sha256, 64, f"{label}.sha256")
    return source_type, repository, ref, urls, sha256


@dataclass(frozen=True)
class ActionSpec:
    """One named, argv-only application action."""

    action_id: str
    argv: tuple[str, ...] = ()
    accepts_input: bool = False
    description: str = ""

    @classmethod
    def from_mapping(cls, action_id: str, raw: Mapping[str, Any]) -> ActionSpec:
        action_id = _content_id(action_id, "action id")
        raw = _mapping(raw, f"action {action_id!r}")
        _known_keys(raw, _ACTION_KEYS, f"action {action_id!r}")
        accepts_input = raw.get("accepts_input", False)
        if type(accepts_input) is not bool:
            raise CatalogError(
                f"action {action_id!r}.accepts_input must be a boolean"
            )
        description = raw.get("description", "")
        if (
            not isinstance(description, str)
            or len(description) > _MAX_TEXT_LENGTH
            or not _valid_text(description)
        ):
            raise CatalogError(
                f"action {action_id!r}.description must be a string"
            )
        return cls(
            action_id=action_id,
            argv=_string_tuple(raw.get("argv"), f"action {action_id!r}.argv"),
            accepts_input=accepts_input,
            description=description,
        )


@dataclass(frozen=True)
class LifecycleSpec:
    """Host-facing application lifetime and fallback policy."""

    single_instance: bool = False
    requires_kilix_session: bool = False
    degrades_inplace: bool = True
    preserve_on_failure: bool = True
    startup_timeout_seconds: int = 0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> LifecycleSpec:
        if raw is None:
            return cls()
        raw = _mapping(raw, "lifecycle")
        _known_keys(raw, _LIFECYCLE_KEYS, "lifecycle")
        values: dict[str, bool] = {}
        defaults = {
            "single_instance": False,
            "requires_kilix_session": False,
            "degrades_inplace": True,
            "preserve_on_failure": True,
        }
        for key, default in defaults.items():
            value = raw.get(key, default)
            if type(value) is not bool:
                raise CatalogError(f"lifecycle.{key} must be a boolean")
            values[key] = value
        timeout = raw.get("startup_timeout_seconds", 0)
        if type(timeout) is not int or not 0 <= timeout <= 3600:
            raise CatalogError(
                "lifecycle.startup_timeout_seconds must be an integer from 0 to 3600"
            )
        return cls(**values, startup_timeout_seconds=timeout)


def _action_specs(value: Any, label: str) -> tuple[ActionSpec, ...]:
    if value is None:
        return ()
    actions = _mapping(value, label)
    if len(actions) > _MAX_ACTIONS:
        raise CatalogError(f"{label} has more than {_MAX_ACTIONS} actions")
    return tuple(
        ActionSpec.from_mapping(action_id, raw)
        for action_id, raw in actions.items()
    )


@dataclass(frozen=True)
class PackageSpec:
    """One immutable installation that may provide several content entries."""

    package_id: str
    source_type: str
    repository: str = ""
    ref: str = ""
    urls: tuple[str, ...] = ()
    sha256: str = ""
    build: tuple[str, ...] = ()
    dependency_hint: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PackageSpec:
        raw = _mapping(raw, "package entry")
        _known_keys(raw, _PACKAGE_KEYS, "package entry")
        try:
            package_id = _content_id(raw["id"], "package id")
            source = raw["source"]
        except KeyError as exc:
            raise CatalogError(f"package entry is missing {exc.args[0]!r}") from exc
        source_type, repository, ref, urls, sha256 = _source_fields(
            source, f"{package_id}.source"
        )
        if source_type not in _INSTALLABLE_SOURCE_TYPES:
            raise CatalogError(
                f"{package_id}: package source must be installable, got "
                f"{source_type!r}"
            )
        dependency_hint = raw.get("dependency_hint", "")
        if (
            not isinstance(dependency_hint, str)
            or len(dependency_hint) > _MAX_TEXT_LENGTH
            or not _valid_text(dependency_hint)
        ):
            raise CatalogError(f"{package_id}: dependency_hint must be a string")
        return cls(
            package_id=package_id,
            source_type=source_type,
            repository=repository,
            ref=ref,
            urls=urls,
            sha256=sha256,
            build=_string_tuple(raw.get("build"), f"{package_id}.build"),
            dependency_hint=dependency_hint,
        )

    def supplies(self, spec: ContentSpec) -> bool:
        """Whether a flattened content specification still matches this package."""
        return (
            spec.package_id == self.package_id
            and spec.source_type == self.source_type
            and spec.repository == self.repository
            and spec.ref == self.ref
            and spec.urls == self.urls
            and spec.sha256 == self.sha256
            and spec.build == self.build
            and spec.dependency_hint == self.dependency_hint
        )


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
    command: tuple[str, ...] = ()
    build: tuple[str, ...] = ()
    dependency_hint: str = ""
    capabilities: tuple[str, ...] = ()
    actions: tuple[ActionSpec, ...] = ()
    accepts: tuple[str, ...] = ()
    lifecycle: LifecycleSpec = LifecycleSpec()
    launch_mode: str = "terminal"
    preferred_size: str = ""
    package_id: str = ""

    def to_mapping(self) -> dict[str, Any]:
        """Return a canonical flattened content-entry mapping.

        Package-provided entries deliberately serialize their resolved source
        fields.  This lets an execution boundary validate the complete object
        without trusting a directly constructed ``PackageSpec``.  The package
        install identity is restored separately by :meth:`canonicalized`.
        """
        if self.source_type == "git":
            source: dict[str, Any] = {
                "ref": self.ref,
                "repository": self.repository,
                "type": "git",
            }
        elif self.source_type == "archive":
            source = {
                "sha256": self.sha256,
                "type": "archive",
                "urls": list(self.urls),
            }
        else:
            source = {"type": self.source_type}

        raw: dict[str, Any] = {
            "accepts": list(self.accepts),
            "actions": {
                action.action_id: {
                    "accepts_input": action.accepts_input,
                    "argv": list(action.argv),
                    "description": action.description,
                }
                for action in self.actions
            },
            "binary": self.binary,
            "build": list(self.build),
            "capabilities": list(self.capabilities),
            "dependency_hint": self.dependency_hint,
            "description": self.description,
            "icon": self.icon,
            "id": self.content_id,
            "kind": self.kind,
            "label": self.label,
            "launch": {
                "mode": self.launch_mode,
                "preferred_size": self.preferred_size,
            },
            "lifecycle": {
                "degrades_inplace": self.lifecycle.degrades_inplace,
                "preserve_on_failure": self.lifecycle.preserve_on_failure,
                "requires_kilix_session": self.lifecycle.requires_kilix_session,
                "single_instance": self.lifecycle.single_instance,
                "startup_timeout_seconds": self.lifecycle.startup_timeout_seconds,
            },
            "source": source,
        }
        if self.command:
            raw["command"] = list(self.command)
        return raw

    def canonicalized(self) -> ContentSpec:
        """Reparse every public field and restore a validated package id."""
        package_id = self.package_id
        if package_id:
            _content_id(package_id, "package id")
        # Call the base implementations explicitly: a directly constructed
        # subclass must not override either side of this trust boundary.
        validated = ContentSpec.from_mapping(ContentSpec.to_mapping(self))
        if package_id:
            validated = replace(validated, package_id=package_id)
        return validated

    @property
    def install_id(self) -> str:
        """Directory/cache identity; shared by entries from the same package."""
        return self.package_id or self.content_id

    def get_action(self, action_id: str) -> ActionSpec | None:
        return next(
            (action for action in self.actions if action.action_id == action_id),
            None,
        )

    def require_action(self, action_id: str) -> ActionSpec:
        action = self.get_action(action_id)
        if action is None:
            raise CatalogError(
                f"{self.content_id}: unknown application action {action_id!r}"
            )
        return action

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        packages: Mapping[str, PackageSpec] | None = None,
    ) -> ContentSpec:
        raw = _mapping(raw, "content entry")
        _known_keys(raw, _ENTRY_KEYS, "content entry")
        try:
            content_id = _content_id(raw["id"], "content id")
            label = raw["label"]
        except KeyError as exc:
            raise CatalogError(f"content entry is missing {exc.args[0]!r}") from exc
        if (
            not isinstance(label, str)
            or not label.strip()
            or len(label) > 256
            or not _valid_text(label)
        ):
            raise CatalogError(f"{content_id}: label must be a non-empty string")

        package_id = raw.get("package", "")
        if not isinstance(package_id, str):
            raise CatalogError(f"{content_id}: package must be a string")
        if package_id:
            _content_id(package_id, "package id")
            if "source" in raw:
                raise CatalogError(f"{content_id}: source and package are mutually exclusive")
            overridden = tuple(
                field for field in ("build", "dependency_hint") if field in raw
            )
            if overridden:
                raise CatalogError(
                    f"{content_id}: package-owned field(s) cannot be overridden: "
                    + ", ".join(overridden)
                )
            package = (packages or {}).get(package_id)
            if package is None:
                raise CatalogError(f"{content_id}: unknown package {package_id!r}")
            source_type = package.source_type
            repository = package.repository
            ref = package.ref
            urls = package.urls
            sha256 = package.sha256
            build = package.build
            dependency_hint = package.dependency_hint
        else:
            try:
                source = raw["source"]
            except KeyError as exc:
                raise CatalogError(
                    f"{content_id}: either source or package is required"
                ) from exc
            source_type, repository, ref, urls, sha256 = _source_fields(
                source, f"{content_id}.source"
            )
            build = _string_tuple(raw.get("build"), f"{content_id}.build")
            dependency_hint = raw.get("dependency_hint", "")
            if (
                not isinstance(dependency_hint, str)
                or len(dependency_hint) > _MAX_TEXT_LENGTH
                or not _valid_text(dependency_hint)
            ):
                raise CatalogError(f"{content_id}: dependency_hint must be a string")

        binary = raw.get("binary", "")
        if not isinstance(binary, str):
            raise CatalogError(f"{content_id}: binary must be a string")
        command = _string_tuple(raw.get("command"), f"{content_id}.command")
        if "command" in raw and not command:
            raise CatalogError(f"{content_id}: command must not be empty")
        launch = raw.get("launch", {})
        launch = _mapping(launch, f"{content_id}.launch")
        _known_keys(launch, _LAUNCH_KEYS, f"{content_id}.launch")
        launch_mode = launch.get("mode", "terminal")
        if not isinstance(launch_mode, str):
            raise CatalogError(f"{content_id}: launch mode must be a string")
        if launch_mode not in _LAUNCH_MODES:
            raise CatalogError(f"{content_id}: unsupported launch mode {launch_mode!r}")

        if binary:
            binary = _relative_path(binary, f"{content_id}.binary")
        if source_type in ("git", "archive") and not binary:
            raise CatalogError(
                f"{content_id}: installable content requires a binary path"
            )
        if source_type in ("git", "archive") and command:
            raise CatalogError(
                f"{content_id}: installable content cannot declare a system command"
            )
        if binary and command:
            raise CatalogError(
                f"{content_id}: binary and command are mutually exclusive"
            )

        actions = _action_specs(raw.get("actions"), f"{content_id}.actions")
        accepts = _string_tuple(
            raw.get("accepts"),
            f"{content_id}.accepts",
            maximum=_MAX_ACCEPTED_INPUTS,
            unique=True,
        )
        lifecycle = LifecycleSpec.from_mapping(raw.get("lifecycle"))

        strings = {}
        for key in ("kind", "icon", "description"):
            value = raw.get(key, "")
            if (
                not isinstance(value, str)
                or len(value) > _MAX_TEXT_LENGTH
                or not _valid_text(value)
            ):
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
            command=command,
            build=build,
            dependency_hint=dependency_hint,
            capabilities=_string_tuple(
                raw.get("capabilities"),
                f"{content_id}.capabilities",
                unique=True,
            ),
            actions=actions,
            accepts=accepts,
            lifecycle=lifecycle,
            launch_mode=launch_mode,
            preferred_size=preferred_size,
            package_id=package_id,
        )


class Catalog:
    """An immutable, uniquely keyed content catalog."""

    def __init__(
        self,
        entries: Iterable[ContentSpec],
        schema_version: int = 1,
        *,
        packages: Iterable[PackageSpec] = (),
        assets: Iterable[AssetSpec] = (),
    ):
        if type(schema_version) is not int or schema_version not in _SCHEMA_VERSIONS:
            raise CatalogError(
                f"unsupported catalog schema version: {schema_version!r}"
            )
        by_package: dict[str, PackageSpec] = {}
        for package in packages:
            if len(by_package) >= _MAX_CONTENT_ENTRIES:
                raise CatalogError(
                    f"catalog has more than {_MAX_CONTENT_ENTRIES} packages"
                )
            if not isinstance(package, PackageSpec):
                raise CatalogError("catalog packages must be PackageSpec instances")
            if package.package_id in by_package:
                raise CatalogError(f"duplicate package id: {package.package_id}")
            by_package[package.package_id] = package
        if schema_version == 1 and by_package:
            raise CatalogError("catalog schema version 1 cannot define packages")
        by_asset: dict[str, AssetSpec] = {}
        for asset in assets:
            if len(by_asset) >= _MAX_ASSETS:
                raise CatalogError(f"catalog has more than {_MAX_ASSETS} assets")
            if not isinstance(asset, AssetSpec):
                raise CatalogError("catalog assets must be AssetSpec instances")
            if asset.asset_id in by_asset:
                raise CatalogError(f"duplicate asset id: {asset.asset_id}")
            by_asset[asset.asset_id] = asset
        if schema_version < 4 and by_asset:
            raise CatalogError("catalog assets require schema version 4")

        by_id: dict[str, ContentSpec] = {}
        provided: dict[str, list[ContentSpec]] = {}
        used_packages: set[str] = set()
        for entry in entries:
            if len(by_id) >= _MAX_CONTENT_ENTRIES:
                raise CatalogError(
                    f"catalog has more than {_MAX_CONTENT_ENTRIES} content entries"
                )
            if not isinstance(entry, ContentSpec):
                raise CatalogError("catalog entries must be ContentSpec instances")
            if schema_version < 3 and (
                entry.command
                or entry.actions
                or entry.accepts
                or entry.lifecycle != LifecycleSpec()
            ):
                raise CatalogError(
                    f"{entry.content_id}: application metadata requires schema version 3"
                )
            if entry.content_id in by_id:
                raise CatalogError(f"duplicate content id: {entry.content_id}")
            if (
                entry.content_id in by_package
                and entry.package_id != entry.content_id
            ):
                raise CatalogError(
                    f"{entry.content_id}: content id conflicts with package install "
                    "identity"
                )
            if entry.package_id:
                package = by_package.get(entry.package_id)
                if package is None:
                    raise CatalogError(
                        f"{entry.content_id}: unknown package {entry.package_id!r}"
                    )
                if not package.supplies(entry):
                    raise CatalogError(
                        f"{entry.content_id}: flattened package metadata does not match "
                        f"{entry.package_id!r}"
                    )
                used_packages.add(entry.package_id)
            by_id[entry.content_id] = entry
            provided.setdefault(entry.install_id, []).append(entry)
        unused = tuple(
            package_id for package_id in by_package if package_id not in used_packages
        )
        if unused:
            raise CatalogError(
                "unused package(s): " + ", ".join(sorted(repr(item) for item in unused))
            )
        self.schema_version = schema_version
        self._entries = tuple(by_id.values())
        self._by_id = MappingProxyType(by_id)
        self._packages = tuple(by_package.values())
        self._by_package = MappingProxyType(by_package)
        self._provided = MappingProxyType(
            {package_id: tuple(items) for package_id, items in provided.items()}
        )
        self._assets = tuple(by_asset.values())
        self._by_asset = MappingProxyType(by_asset)

    @property
    def packages(self) -> tuple[PackageSpec, ...]:
        return self._packages

    @property
    def assets(self) -> tuple[AssetSpec, ...]:
        return self._assets

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

    def get_package(self, package_id: str) -> PackageSpec | None:
        return self._by_package.get(package_id)

    def require_package(self, package_id: str) -> PackageSpec:
        try:
            return self._by_package[package_id]
        except KeyError as exc:
            raise CatalogError(f"unknown package id: {package_id}") from exc

    def provided_by(self, install_id: str) -> tuple[ContentSpec, ...]:
        """Every entry sharing one installation/cache identity."""
        return self._provided.get(install_id, ())

    def get_asset(self, asset_id: str) -> AssetSpec | None:
        return self._by_asset.get(asset_id)

    def require_asset(self, asset_id: str) -> AssetSpec:
        try:
            return self._by_asset[asset_id]
        except KeyError as exc:
            raise CatalogError(f"unknown asset id: {asset_id}") from exc

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> Catalog:
        raw = _mapping(raw, "catalog root")
        _catalog_json_size(raw)
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
        if version not in _SCHEMA_VERSIONS:
            raise CatalogError(f"unsupported catalog schema version: {version!r}")
        if version < 3:
            for item in entries:
                if isinstance(item, Mapping):
                    newer = tuple(
                        key for key in _SCHEMA_THREE_ENTRY_KEYS if key in item
                    )
                    if newer:
                        raise CatalogError(
                            "application metadata field(s) require schema version 3: "
                            + ", ".join(sorted(newer))
                        )
        raw_assets = raw.get("assets", [])
        if not isinstance(raw_assets, list):
            raise CatalogError("catalog assets must be an array")
        if len(raw_assets) > _MAX_ASSETS:
            raise CatalogError(f"catalog has more than {_MAX_ASSETS} asset entries")
        if version < 4 and raw_assets:
            raise CatalogError("catalog assets require schema version 4")
        raw_packages = raw.get("packages", [])
        if not isinstance(raw_packages, list):
            raise CatalogError("catalog packages must be an array")
        if len(raw_packages) > _MAX_CONTENT_ENTRIES:
            raise CatalogError(
                f"catalog has more than {_MAX_CONTENT_ENTRIES} package entries"
            )
        if version == 1 and raw_packages:
            raise CatalogError("catalog schema version 1 cannot define packages")
        packages = tuple(PackageSpec.from_mapping(item) for item in raw_packages)
        by_package: dict[str, PackageSpec] = {}
        for package in packages:
            if package.package_id in by_package:
                raise CatalogError(f"duplicate package id: {package.package_id}")
            by_package[package.package_id] = package
        parsed = tuple(
            ContentSpec.from_mapping(item, packages=by_package) for item in entries
        )
        assets = tuple(AssetSpec.from_mapping(item) for item in raw_assets)
        return cls(parsed, version, packages=packages, assets=assets)

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
            raw = json.loads(
                payload,
                object_pairs_hook=_json_object,
                parse_int=_json_integer,
                parse_float=_reject_json_number,
                parse_constant=_reject_json_number,
            )
        except CatalogError:
            raise
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
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
