"""Validated content-catalog model."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
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
_MAX_ASSETS = 4096
_MAX_ASSET_FILES = 100_000
_ASSET_SOURCE_MODES = frozenset(
    ("upstream-archive", "upstream-files", "upstream-convert", "registry-manifest")
)
_KILIX_HOSTS = frozenset(
    ("github.com", "www.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com")
)
_KILIX_OWNER = "itsmygithubacct"
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


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _byte_count(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise CatalogError(f"{label} must be a non-negative 64-bit integer")
    return value


def _nonempty_text(value: Any, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or not _valid_text(value) or len(value) > maximum:
        raise CatalogError(f"{label} must be a non-empty string")
    return value


def _is_kilix_hosted(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if host in {"github.com", "www.github.com"}:
        return path.lower().startswith(f"/{_KILIX_OWNER}/")
    if host == "raw.githubusercontent.com":
        return path.lower().startswith(f"/{_KILIX_OWNER}/")
    if host == "objects.githubusercontent.com":
        return f"/{_KILIX_OWNER}/" in path.lower()
    return False


def _https_url(value: Any, label: str, *, allow_file: bool = False) -> str:
    value = _nonempty_text(value, label, maximum=4096)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CatalogError(f"{label} has an invalid port") from exc
    if allow_file and parsed.scheme == "file":
        if parsed.netloc and parsed.netloc not in {"", "localhost"}:
            raise CatalogError(f"{label} file URL must be local")
        return value
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
    if _is_kilix_hosted(value):
        raise CatalogError("model bytes must come from upstream (OD-S)")
    host = parsed.hostname.lower()
    if host in {"huggingface.co", "www.huggingface.co"}:
        if "/resolve/" not in parsed.path:
            raise CatalogError(f"{label} Hugging Face URL must use resolve/<commit>")
        after = parsed.path.split("/resolve/", 1)[1]
        commit = after.split("/", 1)[0]
        if len(commit) != 40 or any(character not in _HEX for character in commit.lower()):
            raise CatalogError(f"{label} Hugging Face URL must use resolve/<40-hex>")
    return value


def _input_name(value: Any, label: str) -> str:
    """A converter input's name inside its private input directory.

    The converter maps each of its pinned input names onto `<input dir>/<name>`,
    so a name with a directory part, or one that navigates, is not a name it
    can bind.
    """
    value = _nonempty_text(value, label, maximum=255)
    if "/" in value or "\\" in value or value.startswith(".") or value in {".", ".."}:
        raise CatalogError(f"{label} must be a plain file name")
    return value


def _require_provenance_host(url: str, provenance_url: str, label: str) -> None:
    fetch_host = (urlsplit(url).hostname or "").lower()
    proven_host = (urlsplit(provenance_url).hostname or "").lower()
    if fetch_host != proven_host:
        raise CatalogError(f"{label} fetch host must match provenance host")


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


def _content_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise CatalogError(f"invalid {label}: {value!r}")
    return value


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
    urls = _string_tuple(source.get("urls"), f"{label}.urls")
    sha256 = source.get("sha256", "")
    if source_type == "git":
        if (
            not isinstance(repository, str)
            or not repository
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
        if not isinstance(description, str) or not _valid_text(description):
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
        if not isinstance(dependency_hint, str) or not _valid_text(dependency_hint):
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
        if not isinstance(label, str) or not label.strip() or not _valid_text(label):
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
            if not isinstance(dependency_hint, str) or not _valid_text(
                dependency_hint
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
        accepts = _string_tuple(raw.get("accepts"), f"{content_id}.accepts")
        if len(accepts) > _MAX_ACCEPTED_INPUTS:
            raise CatalogError(
                f"{content_id}.accepts has more than {_MAX_ACCEPTED_INPUTS} inputs"
            )
        lifecycle = LifecycleSpec.from_mapping(raw.get("lifecycle"))

        strings = {}
        for key in ("kind", "icon", "description"):
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
            command=command,
            build=build,
            dependency_hint=dependency_hint,
            capabilities=_string_tuple(
                raw.get("capabilities"), f"{content_id}.capabilities"
            ),
            actions=actions,
            accepts=accepts,
            lifecycle=lifecycle,
            launch_mode=launch_mode,
            preferred_size=preferred_size,
            package_id=package_id,
        )


@dataclass(frozen=True)
class AssetFileSpec:
    """One immutable regular file in an asset manifest."""

    path: str
    bytes: int
    sha256: str

    def to_mapping(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "path": self.path, "sha256": self.sha256}

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], label: str) -> AssetFileSpec:
        raw = _mapping(raw, label)
        _known_keys(raw, frozenset(("path", "bytes", "sha256")), label)
        try:
            path = _relative_path(raw["path"], f"{label}.path")
            size = _byte_count(raw["bytes"], f"{label}.bytes")
            digest = raw["sha256"]
        except KeyError as exc:
            raise CatalogError(f"{label} is missing {exc.args[0]!r}") from exc
        if not isinstance(digest, str):
            raise CatalogError(f"{label}.sha256 must be a string")
        return cls(path, size, _exact_hex(digest, 64, f"{label}.sha256"))


@dataclass(frozen=True)
class AssetLicenseSpec:
    """Licence identity plus the kilix-license record digest (OD-AJ)."""

    license_id: str
    text_sha256: str
    decision: str
    licensors: tuple[str, ...]
    record_digest: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "id": self.license_id,
            "licensors": list(self.licensors),
            "record_digest": self.record_digest,
            "text_sha256": self.text_sha256,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], label: str) -> AssetLicenseSpec:
        raw = _mapping(raw, label)
        _known_keys(
            raw,
            frozenset(("id", "text_sha256", "decision", "licensors", "record_digest")),
            label,
        )
        try:
            license_id = raw["id"]
            digest = raw["text_sha256"]
            decision = raw["decision"]
            record_digest = raw["record_digest"]
        except KeyError as exc:
            raise CatalogError(f"{label} is missing {exc.args[0]!r}") from exc
        if digest is None or digest == "":
            raise CatalogError(f"{label} is missing a licence text digest")
        if not isinstance(license_id, str) or not license_id or not _valid_text(license_id):
            raise CatalogError(f"{label}.id is invalid")
        if decision not in ("informational", "affirmative"):
            raise CatalogError(f"{label}.decision is unsupported")
        licensors_raw = raw.get("licensors")
        if not isinstance(licensors_raw, list) or not 1 <= len(licensors_raw) <= 4:
            raise CatalogError(f"{label}.licensors must be 1..4 strings")
        licensors = tuple(
            _nonempty_text(item, f"{label}.licensors[{index}]", maximum=128)
            for index, item in enumerate(licensors_raw)
        )
        return cls(
            license_id,
            _exact_hex(digest, 64, f"{label}.text_sha256"),
            decision,
            licensors,
            _exact_hex(record_digest, 64, f"{label}.record_digest"),
        )


@dataclass(frozen=True)
class AssetFetchSpec:
    path: str
    url: str

    def to_mapping(self) -> dict[str, Any]:
        return {"path": self.path, "url": self.url}


@dataclass(frozen=True)
class AssetConvertInputSpec:
    """One exact upstream file a converter reads, and never installs.

    `upstream-convert` records whose installed tree is the conversion's own
    output cannot carry their inputs in `files`: the converter is handed a
    private input directory and writes a separate output. Each input is
    therefore pinned here, by exact size and digest, instead of in `files`.
    `path` is the file's name inside that input directory, which the converter
    matches against its own pinned input names, so it is a plain name with no
    directory part.
    """

    path: str
    url: str
    bytes: int
    sha256: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "bytes": self.bytes,
            "path": self.path,
            "sha256": self.sha256,
            "url": self.url,
        }


@dataclass(frozen=True)
class AssetSpec:
    """A validated kilix.content.asset/v3 record."""

    asset_id: str
    label: str
    provider: str
    stream: str
    version: str
    files: tuple[AssetFileSpec, ...]
    source_mode: str
    url: str
    archive_bytes: int
    archive_sha256: str
    archive_format: str
    root: str
    fetch: tuple[AssetFetchSpec, ...]
    convert_url: str
    convert_bytes: int
    convert_sha256: str
    convert_input_path: str
    convert_inputs: tuple[AssetConvertInputSpec, ...]
    convert_tool_asset_id: str
    convert_argv: tuple[str, ...]
    manifest_url: str
    manifest_sha256: str
    blobs: tuple[AssetFetchSpec, ...]
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
        provenance = {
            "original_url": self.provenance_url,
            "project": self.provenance_project,
            "revision": self.provenance_revision,
        }
        if self.source_mode == "upstream-archive":
            source: dict[str, Any] = {
                "archive_bytes": self.archive_bytes,
                "archive_sha256": self.archive_sha256,
                "format": self.archive_format,
                "mode": self.source_mode,
                "provenance": provenance,
                "root": self.root,
                "url": self.url,
            }
        elif self.source_mode == "upstream-files":
            source = {
                "fetch": [{"path": item.path, "url": item.url} for item in self.fetch],
                "mode": self.source_mode,
                "provenance": provenance,
            }
        elif self.source_mode == "upstream-convert":
            convert_input: dict[str, Any] = {
                "bytes": self.convert_bytes,
                "sha256": self.convert_sha256,
                "url": self.convert_url,
            }
            if self.convert_input_path:
                convert_input["path"] = self.convert_input_path
            source = {
                "conversion": {
                    "argv": list(self.convert_argv),
                    "tool_asset_id": self.convert_tool_asset_id,
                },
                "input": convert_input,
                "mode": self.source_mode,
                "provenance": provenance,
            }
            if self.convert_inputs:
                source["inputs"] = [item.to_mapping() for item in self.convert_inputs]
            if self.fetch:
                source["fetch"] = [{"path": item.path, "url": item.url} for item in self.fetch]
        else:
            source = {
                "blobs": [{"path": item.path, "url": item.url} for item in self.blobs],
                "manifest_sha256": self.manifest_sha256,
                "manifest_url": self.manifest_url,
                "mode": self.source_mode,
                "provenance": provenance,
            }
        return {
            "compatibility": {
                "consumer_schema": self.consumer_schema,
                "maximum": self.compatibility_maximum,
                "minimum": self.compatibility_minimum,
            },
            "files": [item.to_mapping() for item in self.files],
            "id": self.asset_id,
            "label": self.label,
            "licenses": [item.to_mapping() for item in self.licenses],
            "provider": self.provider,
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": self.download_bytes,
                "installed_bytes": self.installed_bytes,
                "temporary_bytes": self.temporary_bytes,
            },
            "source": source,
            "stream": self.stream,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_mapping())).hexdigest()

    @property
    def manifest_digest(self) -> str:
        payload = [item.to_mapping() for item in self.files]
        return hashlib.sha256(_canonical_json(payload)).hexdigest()

    @property
    def source_url(self) -> str:
        if self.source_mode == "upstream-archive":
            return self.url
        if self.source_mode == "upstream-files" and self.fetch:
            return self.fetch[0].url
        if self.source_mode == "upstream-convert":
            return self.convert_url
        return self.manifest_url

    @property
    def source_host(self) -> str:
        try:
            return urlsplit(self.source_url).hostname or ""
        except ValueError:
            return ""

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        allow_file_urls: bool = False,
    ) -> AssetSpec:
        raw = _mapping(raw, "asset entry")
        _known_keys(
            raw,
            frozenset(
                (
                    "schema",
                    "id",
                    "label",
                    "provider",
                    "stream",
                    "version",
                    "files",
                    "source",
                    "sizes",
                    "licenses",
                    "compatibility",
                )
            ),
            "asset entry",
        )
        required = (
            "schema",
            "id",
            "label",
            "provider",
            "stream",
            "version",
            "files",
            "source",
            "sizes",
            "licenses",
            "compatibility",
        )
        missing = next((key for key in required if key not in raw), None)
        if missing is not None:
            raise CatalogError(f"asset entry is missing {missing!r}")
        if raw["schema"] != "kilix.content.asset/v3":
            raise CatalogError("asset entry has unsupported schema")
        asset_id = _content_id(raw["id"], "asset id")
        label = _nonempty_text(raw["label"], f"{asset_id}.label")
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
            download_bytes = _byte_count(
                sizes["download_bytes"], f"{asset_id}.sizes.download_bytes"
            )
            installed_bytes = _byte_count(
                sizes["installed_bytes"], f"{asset_id}.sizes.installed_bytes"
            )
            temporary_bytes = _byte_count(
                sizes["temporary_bytes"], f"{asset_id}.sizes.temporary_bytes"
            )
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
            raise CatalogError(f"{asset_id}.licenses contains a duplicate license id")
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
        if "mirrors" in source or "parts" in source:
            raise CatalogError(f"{asset_id}.source must not include mirrors or parts")
        source_mode = source.get("mode")
        if source_mode not in _ASSET_SOURCE_MODES:
            raise CatalogError(f"{asset_id}.source.mode is unsupported")
        provenance = _mapping(source.get("provenance"), f"{asset_id}.source.provenance")
        _known_keys(
            provenance,
            frozenset(("project", "revision", "original_url")),
            f"{asset_id}.source.provenance",
        )
        try:
            provenance_project = _nonempty_text(
                provenance["project"], f"{asset_id}.source.provenance.project"
            )
            provenance_revision = _nonempty_text(
                provenance["revision"], f"{asset_id}.source.provenance.revision"
            )
            provenance_url = _https_url(
                provenance["original_url"],
                f"{asset_id}.source.provenance.original_url",
                allow_file=allow_file_urls,
            )
        except KeyError as exc:
            raise CatalogError(
                f"{asset_id}.source.provenance is missing {exc.args[0]!r}"
            ) from exc
        url = archive_sha256 = archive_format = root = convert_url = convert_sha256 = ""
        convert_input_path = convert_tool_asset_id = manifest_url = manifest_sha256 = ""
        archive_bytes = convert_bytes = 0
        fetch: tuple[AssetFetchSpec, ...] = ()
        convert_argv: tuple[str, ...] = ()
        convert_inputs: tuple[AssetConvertInputSpec, ...] = ()
        blobs: tuple[AssetFetchSpec, ...] = ()
        if source_mode == "upstream-archive":
            _known_keys(
                source,
                frozenset(
                    (
                        "mode",
                        "url",
                        "archive_bytes",
                        "archive_sha256",
                        "format",
                        "root",
                        "provenance",
                    )
                ),
                f"{asset_id}.source",
            )
            try:
                url = _https_url(
                    source["url"], f"{asset_id}.source.url", allow_file=allow_file_urls
                )
                archive_bytes = _byte_count(
                    source["archive_bytes"], f"{asset_id}.source.archive_bytes"
                )
                archive_sha256 = _exact_hex(
                    source["archive_sha256"], 64, f"{asset_id}.source.archive_sha256"
                )
                archive_format = source["format"]
                root = _nonempty_text(source["root"], f"{asset_id}.source.root", maximum=256)
            except KeyError as exc:
                raise CatalogError(f"{asset_id}.source is missing {exc.args[0]!r}") from exc
            if archive_format not in {"zip", "tar"}:
                raise CatalogError(f"{asset_id}.source.format must be zip or tar")
            if "/" in root or root in {".", ".."}:
                raise CatalogError(f"{asset_id}.source.root must be a single directory name")
            _require_provenance_host(url, provenance_url, f"{asset_id}.source.url")
            if download_bytes != archive_bytes:
                raise CatalogError(f"{asset_id}.sizes.download_bytes must equal archive_bytes")
        elif source_mode == "upstream-files":
            _known_keys(
                source,
                frozenset(("mode", "fetch", "provenance")),
                f"{asset_id}.source",
            )
            raw_fetch = source.get("fetch")
            if not isinstance(raw_fetch, list) or not raw_fetch:
                raise CatalogError(f"{asset_id}.source.fetch must be a non-empty array")
            items: list[AssetFetchSpec] = []
            for index, item in enumerate(raw_fetch):
                mapping = _mapping(item, f"{asset_id}.source.fetch[{index}]")
                _known_keys(mapping, frozenset(("path", "url")), f"{asset_id}.source.fetch[{index}]")
                path = _relative_path(
                    mapping.get("path", ""), f"{asset_id}.source.fetch[{index}].path"
                )
                item_url = _https_url(
                    mapping.get("url"),
                    f"{asset_id}.source.fetch[{index}].url",
                    allow_file=allow_file_urls,
                )
                _require_provenance_host(
                    item_url, provenance_url, f"{asset_id}.source.fetch[{index}].url"
                )
                items.append(AssetFetchSpec(path, item_url))
            fetch = tuple(items)
            fetch_paths = {item.path for item in fetch}
            file_paths = {item.path for item in files if not item.path.startswith("notices/")}
            if fetch_paths != file_paths:
                raise CatalogError(f"{asset_id}.source.fetch paths must match files")
        elif source_mode == "upstream-convert":
            _known_keys(
                source,
                frozenset(
                    ("mode", "input", "conversion", "provenance", "fetch", "inputs")
                ),
                f"{asset_id}.source",
            )
            raw_input = _mapping(source.get("input"), f"{asset_id}.source.input")
            _known_keys(
                raw_input,
                frozenset(("url", "bytes", "sha256", "path")),
                f"{asset_id}.source.input",
            )
            convert_url = _https_url(
                raw_input.get("url"),
                f"{asset_id}.source.input.url",
                allow_file=allow_file_urls,
            )
            convert_bytes = _byte_count(
                raw_input.get("bytes"), f"{asset_id}.source.input.bytes"
            )
            convert_sha256 = _exact_hex(
                raw_input.get("sha256"), 64, f"{asset_id}.source.input.sha256"
            )
            _require_provenance_host(
                convert_url, provenance_url, f"{asset_id}.source.input.url"
            )
            if "path" in raw_input:
                convert_input_path = _relative_path(
                    raw_input.get("path", ""), f"{asset_id}.source.input.path"
                )
            raw_inputs = source.get("inputs")
            if raw_inputs is not None:
                if not isinstance(raw_inputs, list) or not raw_inputs:
                    raise CatalogError(
                        f"{asset_id}.source.inputs must be a non-empty array"
                    )
                extra_inputs = []
                for index, item in enumerate(raw_inputs):
                    label = f"{asset_id}.source.inputs[{index}]"
                    mapping = _mapping(item, label)
                    _known_keys(
                        mapping, frozenset(("path", "url", "bytes", "sha256")), label
                    )
                    name = _input_name(mapping.get("path", ""), f"{label}.path")
                    item_url = _https_url(
                        mapping.get("url"), f"{label}.url", allow_file=allow_file_urls
                    )
                    _require_provenance_host(item_url, provenance_url, f"{label}.url")
                    extra_inputs.append(
                        AssetConvertInputSpec(
                            name,
                            item_url,
                            _byte_count(mapping.get("bytes"), f"{label}.bytes"),
                            _exact_hex(mapping.get("sha256"), 64, f"{label}.sha256"),
                        )
                    )
                convert_inputs = tuple(extra_inputs)
            conversion = _mapping(source.get("conversion"), f"{asset_id}.source.conversion")
            _known_keys(
                conversion,
                frozenset(("tool_asset_id", "argv")),
                f"{asset_id}.source.conversion",
            )
            convert_tool_asset_id = _content_id(
                conversion.get("tool_asset_id"), f"{asset_id}.source.conversion.tool_asset_id"
            )
            convert_argv = _string_tuple(
                conversion.get("argv"), f"{asset_id}.source.conversion.argv"
            )
            if not convert_argv:
                raise CatalogError(f"{asset_id}.source.conversion.argv is required")
            raw_fetch = source.get("fetch")
            if raw_fetch is not None:
                if not isinstance(raw_fetch, list) or not raw_fetch:
                    raise CatalogError(f"{asset_id}.source.fetch must be a non-empty array")
                items = []
                for index, item in enumerate(raw_fetch):
                    mapping = _mapping(item, f"{asset_id}.source.fetch[{index}]")
                    _known_keys(
                        mapping, frozenset(("path", "url")), f"{asset_id}.source.fetch[{index}]"
                    )
                    path = _relative_path(
                        mapping.get("path", ""), f"{asset_id}.source.fetch[{index}].path"
                    )
                    item_url = _https_url(
                        mapping.get("url"),
                        f"{asset_id}.source.fetch[{index}].url",
                        allow_file=allow_file_urls,
                    )
                    _require_provenance_host(
                        item_url, provenance_url, f"{asset_id}.source.fetch[{index}].url"
                    )
                    items.append(AssetFetchSpec(path, item_url))
                fetch = tuple(items)
            if convert_inputs:
                # Input-directory mode: the installed tree is the conversion's
                # own output, so no input appears in `files` and `fetch`, which
                # only ever stages installed files, has nothing to do here.
                if fetch:
                    raise CatalogError(
                        f"{asset_id}.source.inputs and fetch are mutually exclusive"
                    )
                if not convert_input_path:
                    raise CatalogError(
                        f"{asset_id}.source.input.path is required with inputs"
                    )
                _input_name(convert_input_path, f"{asset_id}.source.input.path")
                names = [convert_input_path] + [item.path for item in convert_inputs]
                if len(set(names)) != len(names):
                    raise CatalogError(f"{asset_id}.source.inputs names must be distinct")
                listed = {item.path for item in files}
                for name in names:
                    if name in listed:
                        raise CatalogError(
                            f"{asset_id}.source input {name!r} must not be an installed file"
                        )
            elif convert_input_path or fetch:
                extra_paths = {item.path for item in fetch}
                if convert_input_path in extra_paths:
                    raise CatalogError(f"{asset_id}.source.input.path duplicates fetch")
                expected = extra_paths | ({convert_input_path} if convert_input_path else set())
                file_paths = {item.path for item in files if not item.path.startswith("notices/")}
                if expected != file_paths:
                    raise CatalogError(
                        f"{asset_id}.source input/fetch paths must match files"
                    )
                if convert_input_path:
                    listed = next(item for item in files if item.path == convert_input_path)
                    if listed.bytes != convert_bytes or listed.sha256 != convert_sha256:
                        raise CatalogError(
                            f"{asset_id}.source.input must match the listed input file"
                        )
        else:
            _known_keys(
                source,
                frozenset(("mode", "manifest_url", "manifest_sha256", "blobs", "provenance")),
                f"{asset_id}.source",
            )
            manifest_url = _https_url(
                source.get("manifest_url"),
                f"{asset_id}.source.manifest_url",
                allow_file=allow_file_urls,
            )
            manifest_sha256 = _exact_hex(
                source.get("manifest_sha256"), 64, f"{asset_id}.source.manifest_sha256"
            )
            _require_provenance_host(
                manifest_url, provenance_url, f"{asset_id}.source.manifest_url"
            )
            raw_blobs = source.get("blobs")
            if not isinstance(raw_blobs, list) or not raw_blobs:
                raise CatalogError(f"{asset_id}.source.blobs must be a non-empty array")
            blob_items: list[AssetFetchSpec] = []
            for index, item in enumerate(raw_blobs):
                mapping = _mapping(item, f"{asset_id}.source.blobs[{index}]")
                _known_keys(mapping, frozenset(("path", "url")), f"{asset_id}.source.blobs[{index}]")
                blob_items.append(
                    AssetFetchSpec(
                        _relative_path(
                            mapping.get("path", ""),
                            f"{asset_id}.source.blobs[{index}].path",
                        ),
                        _https_url(
                            mapping.get("url"),
                            f"{asset_id}.source.blobs[{index}].url",
                            allow_file=allow_file_urls,
                        ),
                    )
                )
            blobs = tuple(blob_items)
            blob_paths = {item.path for item in blobs}
            file_paths = {item.path for item in files if not item.path.startswith("notices/")}
            if blob_paths != file_paths:
                raise CatalogError(f"{asset_id}.source.blobs paths must match files")
        return cls(
            asset_id=asset_id,
            label=label,
            provider=provider,
            stream=stream,
            version=version,
            files=files,
            source_mode=source_mode,
            url=url,
            archive_bytes=archive_bytes,
            archive_sha256=archive_sha256,
            archive_format=archive_format,
            root=root,
            fetch=fetch,
            convert_url=convert_url,
            convert_bytes=convert_bytes,
            convert_sha256=convert_sha256,
            convert_input_path=convert_input_path,
            convert_inputs=convert_inputs,
            convert_tool_asset_id=convert_tool_asset_id,
            convert_argv=convert_argv,
            manifest_url=manifest_url,
            manifest_sha256=manifest_sha256,
            blobs=blobs,
            provenance_project=provenance_project,
            provenance_revision=provenance_revision,
            provenance_url=provenance_url,
            download_bytes=download_bytes,
            installed_bytes=installed_bytes,
            temporary_bytes=temporary_bytes,
            licenses=licenses,
            consumer_schema=consumer_schema,
            compatibility_minimum=compatibility_minimum,
            compatibility_maximum=compatibility_maximum,
        )


def source_objects_sha256(spec: AssetSpec) -> str:
    """Digest of the upstream objects named by the record (R2-016)."""
    if spec.source_mode == "upstream-archive":
        payload: Any = {
            "archive_bytes": spec.archive_bytes,
            "archive_sha256": spec.archive_sha256,
            "url": spec.url,
        }
    elif spec.source_mode == "upstream-files":
        payload = [
            {"path": item.path, "sha256": next(f.sha256 for f in spec.files if f.path == item.path), "url": item.url}
            for item in spec.fetch
        ]
    elif spec.source_mode == "upstream-convert":
        payload = {
            "bytes": spec.convert_bytes,
            "path": spec.convert_input_path,
            "sha256": spec.convert_sha256,
            "url": spec.convert_url,
        }
        if spec.convert_inputs:
            # Pinned outside `files`, so they must be digested here or two
            # records differing only in their extra inputs would look alike.
            payload["inputs"] = [item.to_mapping() for item in spec.convert_inputs]
        if spec.fetch:
            payload["fetch"] = [
                {
                    "path": item.path,
                    "sha256": next(f.sha256 for f in spec.files if f.path == item.path),
                    "url": item.url,
                }
                for item in spec.fetch
            ]
    else:
        payload = {
            "blobs": [{"path": item.path, "url": item.url} for item in spec.blobs],
            "manifest_sha256": spec.manifest_sha256,
            "manifest_url": spec.manifest_url,
        }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


class Catalog:
    """An immutable, uniquely keyed content catalog."""

    def __init__(
        self,
        entries: Iterable[ContentSpec],
        schema_version: int = 1,
        *,
        packages: Iterable[PackageSpec] = (),
        assets: Iterable[AssetSpec] = (),
        test_authority: bool = False,
    ):
        if type(schema_version) is not int or schema_version not in _SCHEMA_VERSIONS:
            raise CatalogError(
                f"unsupported catalog schema version: {schema_version!r}"
            )
        by_package: dict[str, PackageSpec] = {}
        for package in packages:
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
            if entry.content_id in by_asset:
                raise CatalogError(
                    f"{entry.content_id}: content id conflicts with an asset id"
                )
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
        self.test_authority = test_authority

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
    def from_mapping(
        cls, raw: Mapping[str, Any], *, test_authority: bool = False
    ) -> Catalog:
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
        raw_assets = raw.get("assets", [])
        if not isinstance(raw_assets, list):
            raise CatalogError("catalog assets must be an array")
        if len(raw_assets) > _MAX_ASSETS:
            raise CatalogError(f"catalog has more than {_MAX_ASSETS} asset entries")
        if version < 4 and raw_assets:
            raise CatalogError("catalog assets require schema version 4")
        assets = tuple(
            AssetSpec.from_mapping(item, allow_file_urls=test_authority)
            for item in raw_assets
        )
        return cls(
            parsed,
            version,
            packages=packages,
            assets=assets,
            test_authority=test_authority,
        )

    @classmethod
    def loads(
        cls, payload: str, *, label: str = "catalog", test_authority: bool = False
    ) -> Catalog:
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
        return cls.from_mapping(raw, test_authority=test_authority)

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
