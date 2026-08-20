"""Private, immutable license-receipt storage for non-executable assets.

The public ``kilix.install.license/v1`` receipt is an interchange record, not
an authorization token.  This module wraps it in a private envelope bound to
the effective account, exact release catalog and canonical asset records.
Processes already running as the same effective UID are inside the trust
boundary; hashes are bindings and corruption checks, not a MAC against the
file owner.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import math
import os
import pwd
import re
import secrets
import stat
import threading
import time
import unicodedata
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from .model import AssetSpec

_PUBLIC_SCHEMA = "kilix.install.license/v1"
_PUBLIC_SCHEMA_SHA256 = (
    "2f352856b4bd712e6030b2c74a690f7c0ed250e5730a69aa04b601643dbf1736"
)
_STORE_SCHEMA = "kilix.install.license-store/v1"
_PENDING_SCHEMA = "kilix.install.license-pending/v1"
_KEY_DOMAIN = b"kilix-content license authorization v1\x00"
_RELEASE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_ARTIFACT_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_HEX = re.compile(r"^[a-f0-9]{64}$")
_RECEIPT_NAME = re.compile(r"^([a-f0-9]{64})\.json$")
_TEMP_NAME = re.compile(r"^\.tmp-[a-f0-9]{48}$")
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_LICENSE_TEXT_BYTES = 16 * 1024 * 1024
_MAX_ARTIFACTS = 4096
_MAX_RECEIPTS = 16384
_MAX_INTEGER_DIGITS = 20
_MAX_FLOAT_TOKEN_BYTES = 128
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


class ReceiptError(RuntimeError):
    """A receipt operation failed closed."""


class DecisionInvalid(ReceiptError):
    """A presented decision is structurally or semantically invalid."""


class DecisionDeclined(ReceiptError):
    """The decision does not authorize installation."""


class BindingMismatch(ReceiptError):
    """Decision, release, text, input or asset bindings do not match."""


class ReceiptMissing(ReceiptError):
    """No exact durable receipt covers the requested asset."""


class StoredReceiptInvalid(ReceiptError):
    """Stored receipt state is malformed, corrupt or ambiguously bound."""


class UnsafeStore(ReceiptError):
    """The receipt store path, ownership or mode is unsafe."""


class StoreBusy(ReceiptError):
    """The receipt store lock could not be acquired in time."""


class DurabilityUnknown(ReceiptError):
    """A receipt became visible but durable completion was not confirmed."""


def _valid_text(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
        or any(
            unicodedata.category(character) in ("Cc", "Cf", "Zl", "Zp")
            for character in value
        )
    ):
        raise DecisionInvalid(f"{label} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise DecisionInvalid(f"{label} is not valid UTF-8 text") from exc
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise DecisionInvalid(f"{label} must be a lowercase SHA-256")
    return value


def _release(value: Any) -> str:
    value = _valid_text(value, "release", 256)
    if _RELEASE.fullmatch(value) is None:
        raise DecisionInvalid("release identity is invalid")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DecisionInvalid(f"{label} must be an object")
    return value


def _keys(raw: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    if any(not isinstance(key, str) for key in raw):
        raise DecisionInvalid(f"{label} has a non-string field name")
    unknown = set(raw) - allowed
    if unknown:
        # Field names came from untrusted JSON.  Do not echo them into a
        # terminal-facing diagnostic: they may contain controls or secrets.
        raise DecisionInvalid(f"{label} has unknown field(s)")


def _required(raw: Mapping[str, Any], names: Iterable[str], label: str) -> None:
    missing = [name for name in names if name not in raw]
    if missing:
        raise DecisionInvalid(f"{label} is missing {missing[0]!r}")


def _artifact_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_ARTIFACTS:
        raise DecisionInvalid("artifact_ids must be a bounded nonempty array")
    result: list[str] = []
    for item in value:
        item = _valid_text(item, "artifact id", 128)
        if _ARTIFACT_ID.fullmatch(item) is None:
            raise DecisionInvalid("artifact id is invalid")
        result.append(item)
    if len(result) != len(set(result)):
        raise DecisionInvalid("artifact_ids contains a duplicate")
    return tuple(sorted(result))


def _public_https_url(value: Any, label: str) -> str:
    value = _valid_text(value, label, 4096)
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise DecisionInvalid(f"{label} contains whitespace or control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise DecisionInvalid(f"{label} has an invalid port") from exc
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
        raise DecisionInvalid(f"{label} must be a public HTTPS URL")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _domain_digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StoredReceiptInvalid("stored JSON contains a duplicate field")
        result[key] = value
    return result


def _decision_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecisionInvalid("decision JSON contains a duplicate field")
        result[key] = value
    return result


def _bounded_integer(token: str, error: type[ReceiptError]) -> int:
    digits = token.removeprefix("-")
    if not digits or len(digits) > _MAX_INTEGER_DIGITS:
        raise error("JSON integer exceeds the numeric budget")
    try:
        return int(token)
    except (TypeError, ValueError) as exc:
        raise error("JSON integer is invalid") from exc


def _bounded_float(token: str, error: type[ReceiptError]) -> float:
    if len(token) > _MAX_FLOAT_TOKEN_BYTES:
        raise error("JSON number exceeds the numeric budget")
    try:
        value = float(token)
    except (TypeError, ValueError, OverflowError) as exc:
        raise error("JSON number is invalid") from exc
    if not math.isfinite(value):
        raise error("JSON number is not finite")
    return value


def _decision_integer(token: str) -> int:
    return _bounded_integer(token, DecisionInvalid)


def _decision_float(token: str) -> float:
    return _bounded_float(token, DecisionInvalid)


def _stored_integer(token: str) -> int:
    return _bounded_integer(token, StoredReceiptInvalid)


def _stored_float(token: str) -> float:
    return _bounded_float(token, StoredReceiptInvalid)


@dataclass(frozen=True)
class ReleaseContext:
    """An exact release ID bound to authoritative catalog bytes."""

    release_id: str
    catalog_sha256: str

    @classmethod
    def from_catalog(cls, release_id: str, catalog_bytes: bytes) -> ReleaseContext:
        """Build a synthetic context for tests and pre-integration development."""
        release_id = _release(release_id)
        if not isinstance(catalog_bytes, bytes) or not catalog_bytes:
            raise BindingMismatch("release catalog bytes are required")
        return cls(release_id, hashlib.sha256(catalog_bytes).hexdigest())

    def __post_init__(self) -> None:
        _release(self.release_id)
        _digest(self.catalog_sha256, "catalog_sha256")

    def to_mapping(self) -> dict[str, str]:
        return {"catalog_sha256": self.catalog_sha256, "id": self.release_id}


@dataclass(frozen=True)
class ArtifactBinding:
    """Canonical immutable identity of one asset record and output manifest."""

    artifact_id: str
    version: str
    record_sha256: str
    manifest_sha256: str

    @classmethod
    def from_spec(cls, spec: AssetSpec) -> ArtifactBinding:
        record = _asset_mapping(spec)
        manifest = [
            {"bytes": item.bytes, "path": item.path, "sha256": item.sha256}
            for item in spec.files
        ]
        return cls(
            spec.asset_id,
            spec.version,
            _domain_digest(b"kilix.content.asset/v1 record\x00", record),
            _domain_digest(b"kilix.content.asset/v1 manifest\x00", manifest),
        )

    @classmethod
    def from_mapping(cls, value: Any) -> ArtifactBinding:
        raw = _mapping(value, "artifact binding")
        _keys(
            raw,
            frozenset(("id", "version", "record_sha256", "manifest_sha256")),
            "artifact binding",
        )
        _required(
            raw,
            ("id", "version", "record_sha256", "manifest_sha256"),
            "artifact binding",
        )
        artifact_id = _artifact_ids([raw["id"]])[0]
        return cls(
            artifact_id,
            _valid_text(raw["version"], "asset version", 128),
            _digest(raw["record_sha256"], "asset record digest"),
            _digest(raw["manifest_sha256"], "asset manifest digest"),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "id": self.artifact_id,
            "manifest_sha256": self.manifest_sha256,
            "record_sha256": self.record_sha256,
            "version": self.version,
        }


def _asset_mapping(spec: AssetSpec) -> dict[str, Any]:
    return spec.to_mapping()


def _verify_frozen_schema() -> None:
    """Refuse operation if the packaged public contract is not the frozen one."""
    try:
        schema = (
            resources.files("kilix_content")
            .joinpath("contracts/kilix.install.license-v1.schema.json")
            .read_bytes()
        )
    except (FileNotFoundError, OSError) as exc:
        raise ReceiptError("the frozen license schema is unavailable") from exc
    if hashlib.sha256(schema).hexdigest() != _PUBLIC_SCHEMA_SHA256:
        raise ReceiptError("the packaged license schema does not match its frozen digest")


@dataclass(frozen=True)
class LicenseDecision:
    """A strictly validated presentation result, never an authorization itself."""

    decision_class: str
    license_id: str
    license_text_sha256: str
    artifact_ids: tuple[str, ...]
    release: str
    presenter: str
    outcome: str
    upstream_url: str = ""
    input_sha256: str = ""

    @classmethod
    def loads(cls, document: bytes | str) -> LicenseDecision:
        """Parse bounded UTF-8 JSON without duplicate-key last-wins behavior."""
        if isinstance(document, str):
            try:
                encoded = document.encode("utf-8")
            except UnicodeError as exc:
                raise DecisionInvalid("decision JSON is not valid UTF-8") from exc
        elif isinstance(document, bytes):
            encoded = document
        else:
            raise DecisionInvalid("decision JSON must be bytes or text")
        if len(encoded) > _MAX_DOCUMENT_BYTES:
            raise DecisionInvalid("decision JSON exceeds the byte budget")
        try:
            text = encoded.decode("utf-8")
            value = json.loads(
                text,
                object_pairs_hook=_decision_json_object,
                parse_int=_decision_integer,
                parse_float=_decision_float,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    DecisionInvalid(f"decision JSON contains {token}")
                ),
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise DecisionInvalid("decision JSON is malformed") from exc
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Any) -> LicenseDecision:
        raw = _mapping(value, "license decision")
        allowed = frozenset(
            (
                "schema",
                "kind",
                "decision_class",
                "license_id",
                "license_text_sha256",
                "artifact_ids",
                "release",
                "presenter",
                "outcome",
                "upstream_url",
                "input_sha256",
            )
        )
        _keys(raw, allowed, "license decision")
        _required(
            raw,
            (
                "schema",
                "kind",
                "decision_class",
                "license_id",
                "license_text_sha256",
                "artifact_ids",
                "release",
                "presenter",
                "outcome",
            ),
            "license decision",
        )
        if raw["schema"] != _PUBLIC_SCHEMA or raw["kind"] != "decision":
            raise DecisionInvalid("license decision has an unsupported schema or kind")
        decision_class = raw["decision_class"]
        outcome = raw["outcome"]
        outcomes = {
            "informational": frozenset(("record",)),
            "affirmative": frozenset(("accept", "decline")),
            "user-supplied": frozenset(("supply",)),
            "restricted": frozenset(("decline",)),
        }
        if decision_class not in outcomes or outcome not in outcomes[decision_class]:
            raise DecisionInvalid("decision class and outcome are inconsistent")
        upstream_url = ""
        input_sha256 = ""
        if decision_class == "user-supplied":
            _required(raw, ("upstream_url", "input_sha256"), "license decision")
            upstream_url = _public_https_url(raw["upstream_url"], "upstream_url")
            input_sha256 = _digest(raw["input_sha256"], "input_sha256")
        elif "upstream_url" in raw or "input_sha256" in raw:
            raise DecisionInvalid("input fields are valid only for user-supplied decisions")
        return cls(
            decision_class=decision_class,
            license_id=_valid_text(raw["license_id"], "license_id", 128),
            license_text_sha256=_digest(
                raw["license_text_sha256"], "license_text_sha256"
            ),
            artifact_ids=_artifact_ids(raw["artifact_ids"]),
            release=_release(raw["release"]),
            presenter=_valid_text(raw["presenter"], "presenter", 128),
            outcome=outcome,
            upstream_url=upstream_url,
            input_sha256=input_sha256,
        )

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "artifact_ids": list(self.artifact_ids),
            "decision_class": self.decision_class,
            "kind": "decision",
            "license_id": self.license_id,
            "license_text_sha256": self.license_text_sha256,
            "outcome": self.outcome,
            "presenter": self.presenter,
            "release": self.release,
            "schema": _PUBLIC_SCHEMA,
        }
        if self.decision_class == "user-supplied":
            result["input_sha256"] = self.input_sha256
            result["upstream_url"] = self.upstream_url
        return result


_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)


@dataclass(frozen=True)
class _LicenseReceipt:
    decision_class: str
    license_id: str
    license_text_sha256: str
    artifact_ids: tuple[str, ...]
    release: str
    local_user: str
    recorded_at: str
    outcome: str
    presenter: str
    upstream_url: str = ""
    input_sha256: str = ""

    @classmethod
    def from_mapping(cls, value: Any) -> _LicenseReceipt:
        try:
            raw = _mapping(value, "license receipt")
            allowed = frozenset(
                (
                    "schema",
                    "kind",
                    "decision_class",
                    "license_id",
                    "license_text_sha256",
                    "artifact_ids",
                    "release",
                    "local_user",
                    "recorded_at",
                    "outcome",
                    "presenter",
                    "upstream_url",
                    "input_sha256",
                )
            )
            _keys(raw, allowed, "license receipt")
            _required(
                raw,
                (
                    "schema",
                    "kind",
                    "decision_class",
                    "license_id",
                    "license_text_sha256",
                    "artifact_ids",
                    "release",
                    "local_user",
                    "recorded_at",
                    "outcome",
                    "presenter",
                ),
                "license receipt",
            )
            if raw["schema"] != _PUBLIC_SCHEMA or raw["kind"] != "receipt":
                raise DecisionInvalid("license receipt has an unsupported schema or kind")
            decision_class = raw["decision_class"]
            outcomes = {
                "informational": "recorded",
                "affirmative": "accepted",
                "user-supplied": "supplied",
            }
            if decision_class not in outcomes or raw["outcome"] != outcomes[decision_class]:
                raise DecisionInvalid("receipt class and outcome are inconsistent")
            timestamp = _valid_text(raw["recorded_at"], "recorded_at", 64)
            if _TIMESTAMP.fullmatch(timestamp) is None:
                raise DecisionInvalid("recorded_at is not canonical UTC RFC 3339")
            try:
                parsed = datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
            except ValueError as exc:
                raise DecisionInvalid("recorded_at is invalid") from exc
            if parsed.tzinfo != timezone.utc:
                raise DecisionInvalid("recorded_at must use UTC")
            upstream_url = ""
            input_sha256 = ""
            if decision_class == "user-supplied":
                _required(raw, ("upstream_url", "input_sha256"), "license receipt")
                upstream_url = _public_https_url(raw["upstream_url"], "upstream_url")
                input_sha256 = _digest(raw["input_sha256"], "input_sha256")
            elif "upstream_url" in raw or "input_sha256" in raw:
                raise DecisionInvalid("input fields are valid only for supplied receipts")
            return cls(
                decision_class=decision_class,
                license_id=_valid_text(raw["license_id"], "license_id", 128),
                license_text_sha256=_digest(
                    raw["license_text_sha256"], "license_text_sha256"
                ),
                artifact_ids=_artifact_ids(raw["artifact_ids"]),
                release=_release(raw["release"]),
                local_user=_valid_text(raw["local_user"], "local_user", 256),
                recorded_at=timestamp,
                outcome=raw["outcome"],
                presenter=_valid_text(raw["presenter"], "presenter", 128),
                upstream_url=upstream_url,
                input_sha256=input_sha256,
            )
        except DecisionInvalid as exc:
            raise StoredReceiptInvalid(str(exc)) from exc

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "artifact_ids": list(self.artifact_ids),
            "decision_class": self.decision_class,
            "kind": "receipt",
            "license_id": self.license_id,
            "license_text_sha256": self.license_text_sha256,
            "local_user": self.local_user,
            "outcome": self.outcome,
            "presenter": self.presenter,
            "recorded_at": self.recorded_at,
            "release": self.release,
            "schema": _PUBLIC_SCHEMA,
        }
        if self.decision_class == "user-supplied":
            result["input_sha256"] = self.input_sha256
            result["upstream_url"] = self.upstream_url
        return result

    def decision_mapping(self) -> dict[str, Any]:
        outcomes = {"recorded": "record", "accepted": "accept", "supplied": "supply"}
        result = self.to_mapping()
        result.pop("local_user")
        result.pop("recorded_at")
        result["kind"] = "decision"
        result["outcome"] = outcomes[self.outcome]
        return result


class VerifiedInput:
    """An exact user-supplied file held open across validation and conversion."""

    def __init__(self, path: str, descriptor: int, info: os.stat_result, digest: str):
        self.path = path
        self._descriptor = descriptor
        self._device = info.st_dev
        self._inode = info.st_ino
        self.bytes = info.st_size
        self.sha256 = digest

    @classmethod
    def open(cls, path: str) -> VerifiedInput:
        try:
            path = os.path.abspath(os.fspath(path))
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise BindingMismatch("could not securely open user-supplied input") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise BindingMismatch("user-supplied input is not a regular file")
            digest = cls._digest_descriptor(descriptor)
            return cls(path, descriptor, info, digest)
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _digest_descriptor(descriptor: int) -> str:
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            try:
                block = os.read(descriptor, 1024 * 1024)
            except InterruptedError:
                continue
            if not block:
                break
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest()

    def revalidate(self) -> None:
        try:
            info = os.fstat(self._descriptor)
        except OSError as exc:
            raise BindingMismatch("verified input is no longer open") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_dev != self._device
            or info.st_ino != self._inode
            or info.st_size != self.bytes
            or self._digest_descriptor(self._descriptor) != self.sha256
        ):
            raise BindingMismatch("verified input changed after it was opened")

    def duplicate_descriptor(self) -> int:
        """Return a pinned descriptor for a converter; the caller must close it."""
        self.revalidate()
        return os.dup(self._descriptor)

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, -1
        if descriptor >= 0:
            os.close(descriptor)

    def __enter__(self) -> VerifiedInput:  # noqa: PYI034 -- Python 3.10 support
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _canonical_artifacts(specs: Iterable[AssetSpec]) -> tuple[ArtifactBinding, ...]:
    bindings = tuple(sorted((ArtifactBinding.from_spec(spec) for spec in specs), key=lambda item: item.artifact_id))
    if not bindings or len(bindings) > _MAX_ARTIFACTS:
        raise BindingMismatch("a bounded nonempty artifact set is required")
    ids = tuple(item.artifact_id for item in bindings)
    if len(ids) != len(set(ids)):
        raise BindingMismatch("artifact set contains a duplicate id")
    return bindings


def _successful_outcome(decision_class: str) -> str:
    try:
        return {
            "informational": "recorded",
            "affirmative": "accepted",
            "user-supplied": "supplied",
        }[decision_class]
    except KeyError as exc:
        raise DecisionDeclined(f"{decision_class!r} does not authorize installation") from exc


def _identity(
    uid: int,
    release: ReleaseContext,
    bindings: tuple[ArtifactBinding, ...],
    receipt: _LicenseReceipt,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "artifacts": [item.to_mapping() for item in bindings],
        "decision_class": receipt.decision_class,
        "license_id": receipt.license_id,
        "license_text_sha256": receipt.license_text_sha256,
        "outcome": receipt.outcome,
        "release": release.to_mapping(),
        "schema": _STORE_SCHEMA,
        "uid": uid,
    }
    if receipt.decision_class == "user-supplied":
        result["input"] = {
            "sha256": receipt.input_sha256,
            "upstream_url": receipt.upstream_url,
        }
    return result


def _authorization_key(identity: Mapping[str, Any]) -> str:
    return _domain_digest(_KEY_DOMAIN, identity)


@dataclass(frozen=True)
class _Envelope:
    uid: int
    release: ReleaseContext
    artifacts: tuple[ArtifactBinding, ...]
    decision_sha256: str
    receipt: _LicenseReceipt

    @classmethod
    def create(
        cls,
        uid: int,
        release: ReleaseContext,
        artifacts: tuple[ArtifactBinding, ...],
        decision: LicenseDecision,
        receipt: _LicenseReceipt,
    ) -> _Envelope:
        return cls(
            uid,
            release,
            artifacts,
            _domain_digest(b"kilix.install.license/v1 decision\x00", decision.to_mapping()),
            receipt,
        )

    @classmethod
    def from_mapping(cls, value: Any) -> _Envelope:
        try:
            raw = _mapping(value, "receipt envelope")
            _keys(
                raw,
                frozenset(
                    (
                        "schema",
                        "uid",
                        "release",
                        "artifacts",
                        "decision_sha256",
                        "receipt_schema_sha256",
                        "receipt",
                    )
                ),
                "receipt envelope",
            )
            _required(
                raw,
                (
                    "schema",
                    "uid",
                    "release",
                    "artifacts",
                    "decision_sha256",
                    "receipt_schema_sha256",
                    "receipt",
                ),
                "receipt envelope",
            )
            if raw["schema"] != _STORE_SCHEMA:
                raise DecisionInvalid("receipt envelope has an unsupported schema")
            if raw["receipt_schema_sha256"] != _PUBLIC_SCHEMA_SHA256:
                raise DecisionInvalid("receipt envelope references another public schema")
            uid = raw["uid"]
            if type(uid) is not int or uid < 0:
                raise DecisionInvalid("receipt envelope UID is invalid")
            release_raw = _mapping(raw["release"], "release context")
            _keys(release_raw, frozenset(("id", "catalog_sha256")), "release context")
            _required(release_raw, ("id", "catalog_sha256"), "release context")
            release = ReleaseContext(
                _release(release_raw["id"]),
                _digest(release_raw["catalog_sha256"], "catalog_sha256"),
            )
            artifact_values = raw["artifacts"]
            if not isinstance(artifact_values, list) or not artifact_values or len(artifact_values) > _MAX_ARTIFACTS:
                raise DecisionInvalid("receipt envelope artifacts are invalid")
            artifacts = tuple(ArtifactBinding.from_mapping(item) for item in artifact_values)
            if artifacts != tuple(sorted(artifacts, key=lambda item: item.artifact_id)):
                raise DecisionInvalid("receipt envelope artifacts are not canonical")
            ids = tuple(item.artifact_id for item in artifacts)
            if len(ids) != len(set(ids)):
                raise DecisionInvalid("receipt envelope repeats an artifact")
            receipt = _LicenseReceipt.from_mapping(raw["receipt"])
            if receipt.artifact_ids != ids or receipt.release != release.release_id:
                raise DecisionInvalid("inner receipt is not bound to its envelope")
            decision_sha256 = _digest(raw["decision_sha256"], "decision_sha256")
            expected_decision = _domain_digest(
                b"kilix.install.license/v1 decision\x00", receipt.decision_mapping()
            )
            if decision_sha256 != expected_decision:
                raise DecisionInvalid("stored decision digest does not match its receipt")
            return cls(uid, release, artifacts, decision_sha256, receipt)
        except (DecisionInvalid, StoredReceiptInvalid) as exc:
            if isinstance(exc, StoredReceiptInvalid):
                raise
            raise StoredReceiptInvalid(str(exc)) from exc

    def identity(self) -> dict[str, Any]:
        return _identity(self.uid, self.release, self.artifacts, self.receipt)

    def key(self) -> str:
        return _authorization_key(self.identity())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifacts": [item.to_mapping() for item in self.artifacts],
            "decision_sha256": self.decision_sha256,
            "receipt": self.receipt.to_mapping(),
            "receipt_schema_sha256": _PUBLIC_SCHEMA_SHA256,
            "release": self.release.to_mapping(),
            "schema": _STORE_SCHEMA,
            "uid": self.uid,
        }


@dataclass(frozen=True)
class RecordResult:
    status: str
    key: str
    recorded_at: str


@dataclass(frozen=True)
class ReconcileResult:
    """Outcome of explicitly resolving a durable receipt transaction."""

    status: str
    key: str = ""


@dataclass(frozen=True)
class VerifiedReceipt:
    key: str
    recorded_at: str
    outcome: str


def _validate_node_budget(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise StoredReceiptInvalid("stored receipt nesting is too deep")
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise StoredReceiptInvalid("stored receipt object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise StoredReceiptInvalid("stored receipt field is invalid")
            _validate_node_budget(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > _MAX_ARTIFACTS:
            raise StoredReceiptInvalid("stored receipt array is too large")
        for item in value:
            _validate_node_budget(item, depth + 1)
    elif isinstance(value, str) and len(value) > 4096:
        raise StoredReceiptInvalid("stored receipt string is too large")


def _checked_object(descriptor: int, uid: int, *, directory: bool) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafeStore("could not inspect receipt-store object") from exc
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    mode = _DIRECTORY_MODE if directory else _FILE_MODE
    if (
        not expected
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != mode
        or (not directory and info.st_nlink != 1)
    ):
        raise UnsafeStore("receipt-store object has unsafe type, owner, mode, or links")
    return info


class ReceiptStore:
    """Private descriptor-relative store for exact immutable authorizations."""

    __slots__ = (
        "_clock",
        "_lock_descriptor",
        "_pid",
        "_root_descriptor",
        "_thread_lock",
        "account",
        "root",
        "uid",
    )

    def __init__(
        self,
        root_descriptor: int,
        lock_descriptor: int,
        root: str,
        uid: int,
        account: str,
        *,
        clock: Any = time.time,
    ):
        self._root_descriptor = root_descriptor
        self._lock_descriptor = lock_descriptor
        self.root = root
        self.uid = uid
        self.account = account
        self._clock = clock
        self._pid = os.getpid()
        self._thread_lock = threading.Lock()

    @staticmethod
    def _identity() -> tuple[int, str, str]:
        real_uid = os.getuid()
        effective_uid = os.geteuid()
        if real_uid != effective_uid or effective_uid == 0:
            raise UnsafeStore("receipt storage refuses root or a UID transition")
        try:
            record = pwd.getpwuid(effective_uid)
        except KeyError as exc:
            raise UnsafeStore("effective UID has no NSS identity") from exc
        if not record.pw_name or not os.path.isabs(record.pw_dir):
            raise UnsafeStore("NSS identity has an invalid name or home")
        return effective_uid, record.pw_name, record.pw_dir

    @classmethod
    def open_default(cls, env: Mapping[str, str] | None = None) -> ReceiptStore:
        if cls is not ReceiptStore:
            raise UnsafeStore("the production receipt store cannot be subclass-enabled")
        try:
            _verify_frozen_schema()
            uid, account, nss_home = cls._identity()
            environment = os.environ if env is None else env
            state_home = environment.get("XDG_STATE_HOME", "")
            if state_home:
                if not isinstance(state_home, str) or not os.path.isabs(state_home):
                    raise UnsafeStore("XDG_STATE_HOME must be absolute")
            else:
                state_home = os.path.join(nss_home, ".local", "state")
            base = cls._open_path(state_home, uid, create=True, controlled_leaf=False)
            try:
                root_descriptor = cls._open_controlled_chain(
                    base, ("kilix-content", "license-receipts", "v1"), uid
                )
            finally:
                os.close(base)
            root = os.path.join(
                state_home, "kilix-content", "license-receipts", "v1"
            )
            return ReceiptStore._finish_open(root_descriptor, root, uid, account)
        except ReceiptError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise UnsafeStore("could not securely open the default receipt store") from exc

    @staticmethod
    def _open_path(path: str, uid: int, *, create: bool, controlled_leaf: bool) -> int:
        if not os.path.isabs(path):
            raise UnsafeStore("receipt path must be absolute")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            parts = tuple(part for part in path.split(os.sep) if part)
            for index, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, _DIRECTORY_MODE, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.fchmod(child, _DIRECTORY_MODE)
                    os.fsync(child)
                    os.fsync(descriptor)
                os.close(descriptor)
                descriptor = child
                if controlled_leaf and index == len(parts) - 1:
                    _checked_object(descriptor, uid, directory=True)
            if controlled_leaf and not parts:
                _checked_object(descriptor, uid, directory=True)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _open_controlled_chain(
        base_descriptor: int, parts: tuple[str, ...], uid: int
    ) -> int:
        descriptor = os.dup(base_descriptor)
        try:
            for part in parts:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, _DIRECTORY_MODE, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.fchmod(child, _DIRECTORY_MODE)
                    os.fsync(descriptor)
                _checked_object(child, uid, directory=True)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def _finish_open(
        cls,
        root_descriptor: int,
        root: str,
        uid: int,
        account: str,
        *,
        clock: Any = time.time,
    ) -> ReceiptStore:
        lock_descriptor = -1
        try:
            _checked_object(root_descriptor, uid, directory=True)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            created = False
            try:
                lock_descriptor = os.open(
                    ".lock",
                    flags | os.O_CREAT | os.O_EXCL,
                    _FILE_MODE,
                    dir_fd=root_descriptor,
                )
                created = True
            except FileExistsError:
                lock_descriptor = os.open(
                    ".lock", flags, dir_fd=root_descriptor
                )
            if created:
                os.fchmod(lock_descriptor, _FILE_MODE)
            _checked_object(lock_descriptor, uid, directory=False)
            if created:
                os.fsync(lock_descriptor)
                os.fsync(root_descriptor)
            store = cls(
                root_descriptor,
                lock_descriptor,
                root,
                uid,
                account,
                clock=clock,
            )
            try:
                with store._locked():
                    store._cleanup_temporaries()
                    store._ensure_format_marker()
            except Exception:
                store.close()
                lock_descriptor = -1
                root_descriptor = -1
                raise
            return store
        except Exception:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            if root_descriptor >= 0:
                os.close(root_descriptor)
            raise

    def close(self) -> None:
        lock_descriptor, self._lock_descriptor = self._lock_descriptor, -1
        root_descriptor, self._root_descriptor = self._root_descriptor, -1
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)

    def __enter__(self) -> ReceiptStore:  # noqa: PYI034 -- Python 3.10 support
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _require_release_authority(self, release: ReleaseContext) -> None:
        if not isinstance(release, ReleaseContext):
            raise BindingMismatch("an exact release context is required")
        raise BindingMismatch(
            "production authorization is disabled until the immutable "
            "release-catalog snapshot loader supplies catalog-bound artifacts"
        )

    def _require_current_identity(self) -> None:
        if (
            os.getpid() != self._pid
            or
            os.getuid() != self.uid
            or os.geteuid() != self.uid
            or self.uid == 0
        ):
            raise UnsafeStore("receipt store cannot cross a process or UID transition")

    def _create_fixed_file(self, target: str, document: bytes, label: str) -> bool:
        """Publish one immutable same-directory file without replacing a name."""
        descriptor = -1
        temporary = ""
        visible = False
        try:
            for _attempt in range(16):
                temporary = f".tmp-{secrets.token_hex(24)}"
                try:
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        _FILE_MODE,
                        dir_fd=self._root_descriptor,
                    )
                    break
                except FileExistsError:
                    temporary = ""
            else:
                raise ReceiptError(f"could not allocate a private {label} temporary")
            os.fchmod(descriptor, _FILE_MODE)
            _checked_object(descriptor, self.uid, directory=False)
            self._write_all(descriptor, document)
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            observed = bytearray()
            while len(observed) <= len(document):
                try:
                    block = os.read(
                        descriptor, len(document) + 1 - len(observed)
                    )
                except InterruptedError:
                    continue
                if not block:
                    break
                observed.extend(block)
            if bytes(observed) != document:
                raise OSError(errno.EIO, f"{label} write verification failed")
            try:
                os.link(
                    temporary,
                    target,
                    src_dir_fd=self._root_descriptor,
                    dst_dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
                visible = True
            except FileExistsError:
                return False
            os.unlink(temporary, dir_fd=self._root_descriptor)
            temporary = ""
            os.fsync(self._root_descriptor)
            return True
        except ReceiptError:
            raise
        except OSError as exc:
            if visible:
                raise DurabilityUnknown(
                    f"{label} became visible without confirmed directory durability"
                ) from exc
            raise ReceiptError(f"could not durably create {label}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=self._root_descriptor)
                except OSError:
                    pass

    def _validate_format_marker(self) -> None:
        expected = _canonical_bytes({"schema": _STORE_SCHEMA})
        try:
            observed = self._read_bytes(".format")
        except FileNotFoundError as exc:
            raise UnsafeStore("receipt store format marker disappeared") from exc
        if observed != expected:
            raise UnsafeStore("receipt store has an unknown or corrupt format marker")

    def _ensure_format_marker(self) -> None:
        try:
            self._validate_format_marker()
            return
        except FileNotFoundError:
            pass
        except UnsafeStore as exc:
            try:
                os.stat(
                    ".format",
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise exc
        self._create_fixed_file(
            ".format", _canonical_bytes({"schema": _STORE_SCHEMA}), "format marker"
        )
        self._validate_format_marker()

    @staticmethod
    def _pending_document(target: str) -> bytes:
        if _RECEIPT_NAME.fullmatch(target) is None:
            raise StoredReceiptInvalid("pending receipt target is invalid")
        return _canonical_bytes({"schema": _PENDING_SCHEMA, "target": target})

    def _read_pending(self) -> str:
        document = self._read_bytes(".pending")
        try:
            value = json.loads(
                document,
                object_pairs_hook=_json_object,
                parse_int=_stored_integer,
                parse_float=_stored_float,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    StoredReceiptInvalid(f"pending JSON contains {token}")
                ),
            )
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise StoredReceiptInvalid("pending receipt state is malformed") from exc
        _validate_node_budget(value)
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema", "target"}
            or value.get("schema") != _PENDING_SCHEMA
            or not isinstance(value.get("target"), str)
        ):
            raise StoredReceiptInvalid("pending receipt state is invalid")
        target = value["target"]
        if _RECEIPT_NAME.fullmatch(target) is None:
            raise StoredReceiptInvalid("pending receipt target is invalid")
        if document != self._pending_document(target):
            raise StoredReceiptInvalid("pending receipt state is not canonical")
        return target

    def _require_no_pending(self) -> None:
        try:
            self._read_pending()
        except FileNotFoundError:
            return
        raise DurabilityUnknown(
            "receipt authorization is blocked until explicit reconciliation"
        )

    def _clear_pending(self, target: str) -> None:
        if self._read_pending() != target:
            raise StoredReceiptInvalid("pending receipt target changed")
        document = self._pending_document(target)
        try:
            os.unlink(".pending", dir_fd=self._root_descriptor)
        except OSError as exc:
            raise DurabilityUnknown("could not clear pending receipt state") from exc
        try:
            os.fsync(self._root_descriptor)
        except OSError as exc:
            # Keep the live namespace fail-closed even when persistence of the
            # removal cannot be confirmed. The receipt itself is already synced.
            try:
                self._create_fixed_file(".pending", document, "pending marker")
            except ReceiptError:
                pass
            raise DurabilityUnknown(
                "pending receipt cleanup has unknown durability"
            ) from exc

    def _cleanup_temporaries(self) -> None:
        self._require_current_identity()
        try:
            names = tuple(os.listdir(self._root_descriptor))
        except OSError as exc:
            raise UnsafeStore("could not inspect receipt temporaries") from exc
        changed = False
        linked_targets: list[str] = []
        for name in names:
            if not name.startswith(".tmp-"):
                continue
            if _TEMP_NAME.fullmatch(name) is None:
                raise UnsafeStore("receipt store contains an ambiguous temporary name")
            try:
                info = os.stat(
                    name, dir_fd=self._root_descriptor, follow_symlinks=False
                )
            except OSError as exc:
                raise UnsafeStore("could not inspect a receipt temporary") from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.uid
                or stat.S_IMODE(info.st_mode) != _FILE_MODE
                or info.st_nlink not in (1, 2)
            ):
                raise UnsafeStore("receipt temporary is unsafe")
            linked_target = ""
            if info.st_nlink == 2:
                matches = []
                for candidate in names:
                    if (
                        _RECEIPT_NAME.fullmatch(candidate) is None
                        and candidate not in (".format", ".pending")
                    ):
                        continue
                    try:
                        candidate_info = os.stat(
                            candidate,
                            dir_fd=self._root_descriptor,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise UnsafeStore(
                            "could not inspect a linked receipt temporary"
                        ) from exc
                    if (
                        candidate_info.st_dev == info.st_dev
                        and candidate_info.st_ino == info.st_ino
                    ):
                        matches.append(candidate)
                if len(matches) != 1:
                    raise UnsafeStore(
                        "linked receipt temporary has no unique target"
                    )
                linked_target = matches[0]
            try:
                os.unlink(name, dir_fd=self._root_descriptor)
            except OSError as exc:
                raise UnsafeStore("could not remove a receipt temporary") from exc
            changed = True
            if linked_target:
                linked_targets.append(linked_target)
        if changed:
            try:
                os.fsync(self._root_descriptor)
            except OSError as exc:
                raise DurabilityUnknown(
                    "temporary recovery changed visible receipt state without "
                    "confirmed directory durability"
                ) from exc
            for target in linked_targets:
                if target == ".format":
                    self._validate_format_marker()
                elif target == ".pending":
                    self._read_pending()
                else:
                    self._read_envelope(target)

    @contextmanager
    def _locked(self, *, timeout: float = 5.0):
        if self._lock_descriptor < 0:
            raise UnsafeStore("receipt store is closed")
        # Check before touching a possibly inherited locked mutex after fork.
        self._require_current_identity()
        deadline = time.monotonic() + timeout
        remaining = max(0.0, deadline - time.monotonic())
        if not self._thread_lock.acquire(timeout=remaining):
            raise StoreBusy("receipt store remained locked in this process")
        flock_held = False
        try:
            self._require_current_identity()
            _checked_object(self._root_descriptor, self.uid, directory=True)
            held = _checked_object(self._lock_descriptor, self.uid, directory=False)
            try:
                named = os.stat(
                    ".lock", dir_fd=self._root_descriptor, follow_symlinks=False
                )
            except OSError as exc:
                raise UnsafeStore("receipt-store lock path is unavailable") from exc
            if (
                named.st_dev != held.st_dev
                or named.st_ino != held.st_ino
                or not stat.S_ISREG(named.st_mode)
                or named.st_uid != self.uid
                or stat.S_IMODE(named.st_mode) != _FILE_MODE
                or named.st_nlink != 1
            ):
                raise UnsafeStore("receipt-store lock path was replaced or is unsafe")
            while True:
                try:
                    fcntl.flock(
                        self._lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                    flock_held = True
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise StoreBusy("receipt store remained locked") from exc
                    time.sleep(0.01)
                except InterruptedError:
                    continue
                except OSError as exc:
                    raise ReceiptError("receipt-store locking is unavailable") from exc
            yield
        finally:
            try:
                if flock_held:
                    fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                self._thread_lock.release()

    @staticmethod
    def _timestamp(value: float) -> str:
        try:
            moment = datetime.fromtimestamp(value, timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError) as exc:
            raise ReceiptError("receipt clock produced an invalid timestamp") from exc
        if moment.microsecond:
            return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")
        return moment.isoformat(timespec="seconds").replace("+00:00", "Z")

    def _read_bytes(self, name: str) -> bytes:
        self._require_current_identity()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise UnsafeStore(f"could not securely open stored receipt {name}") from exc
        try:
            _checked_object(descriptor, self.uid, directory=False)
            result = bytearray()
            while len(result) <= _MAX_DOCUMENT_BYTES:
                try:
                    block = os.read(descriptor, min(65536, _MAX_DOCUMENT_BYTES + 1 - len(result)))
                except InterruptedError:
                    continue
                if not block:
                    break
                result.extend(block)
            if len(result) > _MAX_DOCUMENT_BYTES:
                raise StoredReceiptInvalid("stored receipt exceeds the byte budget")
            return bytes(result)
        finally:
            os.close(descriptor)

    def _read_envelope(self, name: str) -> _Envelope:
        match = _RECEIPT_NAME.fullmatch(name)
        if match is None:
            raise StoredReceiptInvalid("receipt filename is invalid")
        document = self._read_bytes(name)
        try:
            value = json.loads(
                document,
                object_pairs_hook=_json_object,
                parse_int=_stored_integer,
                parse_float=_stored_float,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    StoredReceiptInvalid(f"stored JSON contains {token}")
                ),
            )
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise StoredReceiptInvalid("stored receipt is not strict UTF-8 JSON") from exc
        _validate_node_budget(value)
        envelope = _Envelope.from_mapping(value)
        if envelope.uid != self.uid:
            raise StoredReceiptInvalid("stored receipt belongs to another UID")
        if envelope.key() != match.group(1):
            raise StoredReceiptInvalid("stored receipt filename does not match its binding")
        if document != _canonical_bytes(envelope.to_mapping()):
            raise StoredReceiptInvalid("stored receipt bytes are not canonical")
        return envelope

    @staticmethod
    def _write_all(descriptor: int, document: bytes) -> None:
        view = memoryview(document)
        written = 0
        while written < len(view):
            try:
                count = os.write(descriptor, view[written:])
            except InterruptedError:
                continue
            if count <= 0:
                raise OSError(errno.EIO, "short receipt write")
            written += count

    @staticmethod
    def _validate_record_request(
        decision: LicenseDecision,
        text: bytes,
        release: ReleaseContext,
        specs: tuple[AssetSpec, ...],
        verified_input: VerifiedInput | None,
    ) -> tuple[ArtifactBinding, ...]:
        if not isinstance(decision, LicenseDecision):
            raise DecisionInvalid("record requires a validated LicenseDecision")
        if not isinstance(text, bytes) or len(text) > _MAX_LICENSE_TEXT_BYTES:
            raise BindingMismatch("presented license text must be bounded exact bytes")
        if hashlib.sha256(text).hexdigest() != decision.license_text_sha256:
            raise BindingMismatch("presented license text digest does not match decision")
        if decision.release != release.release_id:
            raise BindingMismatch("decision release does not match trusted release")
        bindings = _canonical_artifacts(specs)
        ids = tuple(item.artifact_id for item in bindings)
        if decision.artifact_ids != ids:
            raise BindingMismatch("decision artifacts do not match trusted artifacts")
        for spec in specs:
            matching = tuple(
                item
                for item in spec.licenses
                if item.license_id == decision.license_id
            )
            if len(matching) != 1:
                raise BindingMismatch("license does not apply exactly once to every artifact")
            license_spec = matching[0]
            if (
                license_spec.text_sha256 != decision.license_text_sha256
                or license_spec.decision != decision.decision_class
            ):
                raise BindingMismatch("decision does not match trusted license requirement")
        if decision.outcome == "decline" or decision.decision_class == "restricted":
            raise DecisionDeclined("license decision does not authorize installation")
        _successful_outcome(decision.decision_class)
        if decision.decision_class == "user-supplied":
            if verified_input is None:
                raise BindingMismatch("user-supplied decision requires a verified open input")
            verified_input.revalidate()
            for spec in specs:
                if (
                    spec.source_mode != "user-supplied"
                    or decision.upstream_url != spec.official_url
                    or decision.input_sha256 != spec.input_sha256
                    or verified_input.sha256 != spec.input_sha256
                    or verified_input.bytes != spec.input_bytes
                ):
                    raise BindingMismatch("verified input does not match trusted asset source")
        elif verified_input is not None:
            raise BindingMismatch("verified input is valid only for user-supplied decisions")
        return bindings

    def record(
        self,
        decision: LicenseDecision,
        presented_license_text: bytes,
        release: ReleaseContext,
        artifacts: Iterable[AssetSpec],
        *,
        verified_input: VerifiedInput | None = None,
    ) -> RecordResult:
        """Derive, durably create, and reopen one immutable authorization."""
        _verify_frozen_schema()
        self._require_release_authority(release)
        if not isinstance(decision, LicenseDecision):
            raise DecisionInvalid("record requires a LicenseDecision")
        # The frozen dataclass is convenient for callers, but construction is
        # never validation. Reparse its complete public representation here.
        decision = LicenseDecision.from_mapping(decision.to_mapping())
        specs = tuple(artifacts)
        bindings = self._validate_record_request(
            decision, presented_license_text, release, specs, verified_input
        )
        receipt = _LicenseReceipt(
            decision_class=decision.decision_class,
            license_id=decision.license_id,
            license_text_sha256=decision.license_text_sha256,
            artifact_ids=tuple(item.artifact_id for item in bindings),
            release=release.release_id,
            local_user=self.account,
            recorded_at=self._timestamp(self._clock()),
            outcome=_successful_outcome(decision.decision_class),
            presenter=decision.presenter,
            upstream_url=decision.upstream_url,
            input_sha256=decision.input_sha256,
        )
        envelope = _Envelope.create(self.uid, release, bindings, decision, receipt)
        envelope = _Envelope.from_mapping(envelope.to_mapping())
        key = envelope.key()
        target = f"{key}.json"
        document = _canonical_bytes(envelope.to_mapping())
        if len(document) > _MAX_DOCUMENT_BYTES:
            raise ReceiptError("receipt envelope exceeds the byte budget")
        with self._locked():
            self._cleanup_temporaries()
            self._require_no_pending()
            try:
                existing = self._read_envelope(target)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing.identity() != envelope.identity():
                    raise StoredReceiptInvalid("receipt key collides with different content")
                return RecordResult("existing", key, existing.receipt.recorded_at)
            pending_created = self._create_fixed_file(
                ".pending", self._pending_document(target), "pending marker"
            )
            if not pending_created:
                raise DurabilityUnknown(
                    "another receipt transaction requires explicit reconciliation"
                )
            try:
                if self._read_pending() != target:
                    raise StoredReceiptInvalid("pending receipt target changed")
                created = self._create_fixed_file(target, document, "receipt")
                if not created:
                    # A same-UID writer outside the supported API may have raced
                    # the lock. Establish durability before considering its file.
                    os.fsync(self._root_descriptor)
                stored = self._read_envelope(target)
                if stored.to_mapping() != envelope.to_mapping():
                    raise StoredReceiptInvalid("new receipt changed during durable creation")
                self._clear_pending(target)
                return RecordResult(
                    "created" if created else "existing",
                    key,
                    stored.receipt.recorded_at,
                )
            except DurabilityUnknown:
                raise
            except (ReceiptError, OSError) as exc:
                raise DurabilityUnknown(
                    "receipt transaction requires explicit reconciliation"
                ) from exc

    def reconcile(self) -> ReconcileResult:
        """Durably resolve one interrupted transaction before authorization."""
        with self._locked():
            self._cleanup_temporaries()
            try:
                target = self._read_pending()
            except FileNotFoundError:
                return ReconcileResult("clean")
            key = target.removesuffix(".json")
            try:
                os.stat(
                    target,
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                self._clear_pending(target)
                return ReconcileResult("aborted", key)
            except OSError as exc:
                raise UnsafeStore("could not inspect pending receipt target") from exc

            descriptor = -1
            try:
                stored = self._read_envelope(target)
                descriptor = os.open(
                    target,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=self._root_descriptor,
                )
                _checked_object(descriptor, self.uid, directory=False)
                os.fsync(descriptor)
                os.fsync(self._root_descriptor)
                if self._read_envelope(target).to_mapping() != stored.to_mapping():
                    raise StoredReceiptInvalid(
                        "pending receipt changed during reconciliation"
                    )
                self._clear_pending(target)
                return ReconcileResult("committed", key)
            except DurabilityUnknown:
                raise
            except (StoredReceiptInvalid, UnsafeStore):
                raise
            except OSError as exc:
                raise DurabilityUnknown(
                    "pending receipt durability could not be reconciled"
                ) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

    @staticmethod
    def _covers(
        envelope: _Envelope,
        release: ReleaseContext,
        binding: ArtifactBinding,
        spec: AssetSpec,
        license_id: str,
    ) -> bool:
        if envelope.release != release or binding not in envelope.artifacts:
            return False
        receipt = envelope.receipt
        requirement = next(
            (item for item in spec.licenses if item.license_id == license_id), None
        )
        if requirement is None:
            return False
        if (
            receipt.license_id != requirement.license_id
            or receipt.license_text_sha256 != requirement.text_sha256
            or receipt.decision_class != requirement.decision
            or receipt.outcome != _successful_outcome(requirement.decision)
        ):
            return False
        if requirement.decision == "user-supplied":
            return (
                receipt.upstream_url == spec.official_url
                and receipt.input_sha256 == spec.input_sha256
            )
        return True

    def _receipt_names(self) -> tuple[str, ...]:
        self._require_current_identity()
        _checked_object(self._root_descriptor, self.uid, directory=True)
        try:
            names = tuple(
                name
                for name in os.listdir(self._root_descriptor)
                if _RECEIPT_NAME.fullmatch(name) is not None
            )
        except OSError as exc:
            raise UnsafeStore("could not inspect receipt store") from exc
        if len(names) > _MAX_RECEIPTS:
            raise UnsafeStore("receipt store exceeds its inspection budget")
        return tuple(sorted(names))

    def require_asset(
        self, spec: AssetSpec, release: ReleaseContext
    ) -> tuple[VerifiedReceipt, ...]:
        """Require exact coverage for every license before returning asset paths."""
        _verify_frozen_schema()
        self._require_release_authority(release)
        with self._locked():
            self._cleanup_temporaries()
            self._require_no_pending()
            binding = ArtifactBinding.from_spec(spec)
            results: list[VerifiedReceipt] = []
            names = self._receipt_names()
            for requirement in spec.licenses:
                if requirement.decision == "restricted":
                    raise ReceiptMissing("restricted content cannot be authorized")
                expected_receipt = _LicenseReceipt(
                    requirement.decision,
                    requirement.license_id,
                    requirement.text_sha256,
                    (spec.asset_id,),
                    release.release_id,
                    self.account,
                    "1970-01-01T00:00:00Z",
                    _successful_outcome(requirement.decision),
                    "lookup",
                    (
                        spec.official_url
                        if requirement.decision == "user-supplied"
                        else ""
                    ),
                    (
                        spec.input_sha256
                        if requirement.decision == "user-supplied"
                        else ""
                    ),
                )
                direct_name = (
                    _authorization_key(
                        _identity(self.uid, release, (binding,), expected_receipt)
                    )
                    + ".json"
                )
                found: VerifiedReceipt | None = None
                if direct_name in names:
                    # A corrupt exact single-asset receipt must never be skipped
                    # in favor of a weaker batch match encountered first.
                    envelope = self._read_envelope(direct_name)
                    if self._covers(
                        envelope,
                        release,
                        binding,
                        spec,
                        requirement.license_id,
                    ):
                        found = VerifiedReceipt(
                            envelope.key(),
                            envelope.receipt.recorded_at,
                            envelope.receipt.outcome,
                        )
                if found is None:
                    for name in names:
                        if name == direct_name:
                            continue
                        try:
                            envelope = self._read_envelope(name)
                        except (StoredReceiptInvalid, UnsafeStore):
                            continue
                        if self._covers(
                            envelope,
                            release,
                            binding,
                            spec,
                            requirement.license_id,
                        ):
                            found = VerifiedReceipt(
                                envelope.key(),
                                envelope.receipt.recorded_at,
                                envelope.receipt.outcome,
                            )
                            break
                if found is None:
                    raise ReceiptMissing(
                        "no exact durable receipt covers the requested asset license"
                    )
                results.append(found)
            return tuple(results)

    def list_metadata(self) -> tuple[dict[str, Any], ...]:
        """Return private local metadata; malformed records fail inspection."""
        with self._locked():
            self._cleanup_temporaries()
            self._require_no_pending()
            result = []
            for name in self._receipt_names():
                envelope = self._read_envelope(name)
                result.append(
                    {
                        "artifact_ids": list(envelope.receipt.artifact_ids),
                        "decision_class": envelope.receipt.decision_class,
                        "key": envelope.key(),
                        "license_id": envelope.receipt.license_id,
                        "recorded_at": envelope.receipt.recorded_at,
                    }
                )
            return tuple(result)

    def export_redacted(self) -> bytes:
        """Export non-authoritative bindings without private activity metadata."""
        with self._locked():
            self._cleanup_temporaries()
            self._require_no_pending()
            records = []
            for name in self._receipt_names():
                envelope = self._read_envelope(name)
                records.append(
                    {
                        "artifact_bindings": [
                            {
                                "artifact_id": binding.artifact_id,
                                "manifest_sha256": binding.manifest_sha256,
                                "record_sha256": binding.record_sha256,
                            }
                            for binding in envelope.artifacts
                        ],
                        "artifact_ids": list(envelope.receipt.artifact_ids),
                        "decision_class": envelope.receipt.decision_class,
                        "license_id": envelope.receipt.license_id,
                        "license_text_sha256": envelope.receipt.license_text_sha256,
                        "outcome": envelope.receipt.outcome,
                        "release": envelope.release.release_id,
                    }
                )
            return _canonical_bytes(
                {
                    "authorizations": records,
                    "redacted_fields": [
                        "catalog_sha256",
                        "decision_sha256",
                        "input_sha256",
                        "local_user",
                        "presenter",
                        "receipt_schema_sha256",
                        "recorded_at",
                        "uid",
                        "upstream_url",
                    ],
                    "schema": "kilix.install.license-redacted/v1",
                }
            )

    def export_redacted_to(self, destination: str) -> None:
        """Atomically write a redacted export into an exact private directory."""
        document = self.export_redacted()
        try:
            raw_destination = os.fspath(destination)
            if not isinstance(raw_destination, str):
                raise TypeError("redacted export destination must be text")
            destination = os.path.abspath(raw_destination)
            parent, name = os.path.split(destination)
        except (TypeError, ValueError, OSError) as exc:
            raise ReceiptError("redacted export destination is invalid") from exc
        try:
            encoded_name = os.fsencode(name)
        except (UnicodeError, ValueError) as exc:
            raise ReceiptError("redacted export destination is invalid") from exc
        if (
            not name
            or name in (".", "..")
            or b"\x00" in encoded_name
            or len(encoded_name) > 255
        ):
            raise ReceiptError("redacted export destination is invalid")
        try:
            parent_descriptor = self._open_path(
                parent, self.uid, create=False, controlled_leaf=True
            )
        except ReceiptError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise UnsafeStore(
                "redacted export parent is missing, inaccessible, or unsafe"
            ) from exc
        descriptor = -1
        temporary = f".{name}.tmp-{secrets.token_hex(16)}"
        visible = False
        try:
            try:
                existing = os.stat(
                    name, dir_fd=parent_descriptor, follow_symlinks=False
                )
            except FileNotFoundError:
                existing = None
            except (OSError, ValueError) as exc:
                raise ReceiptError(
                    "could not inspect redacted export destination"
                ) from exc
            if existing is not None:
                if (
                    not stat.S_ISREG(existing.st_mode)
                    or existing.st_uid != self.uid
                    or stat.S_IMODE(existing.st_mode) != _FILE_MODE
                    or existing.st_nlink != 1
                ):
                    raise UnsafeStore(
                        "redacted export destination has unsafe type, owner, mode, or links"
                    )
                raise ReceiptError("redacted export destination already exists")
            descriptor = os.open(
                temporary,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                _FILE_MODE,
                dir_fd=parent_descriptor,
            )
            os.fchmod(descriptor, _FILE_MODE)
            _checked_object(descriptor, self.uid, directory=False)
            self._write_all(descriptor, document)
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            observed = bytearray()
            while len(observed) <= len(document):
                try:
                    block = os.read(
                        descriptor, len(document) + 1 - len(observed)
                    )
                except InterruptedError:
                    continue
                if not block:
                    break
                observed.extend(block)
            if bytes(observed) != document:
                raise OSError(errno.EIO, "redacted export verification failed")
            os.link(
                temporary,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            visible = True
            os.unlink(temporary, dir_fd=parent_descriptor)
            temporary = ""
            os.fsync(parent_descriptor)
            check = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
            try:
                _checked_object(check, self.uid, directory=False)
            finally:
                os.close(check)
        except ReceiptError:
            raise
        except (OSError, ValueError) as exc:
            if visible:
                raise DurabilityUnknown(
                    "redacted export is visible with unknown durability"
                ) from exc
            raise ReceiptError("could not atomically write redacted export") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_descriptor)
                except (OSError, ValueError):
                    pass
            os.close(parent_descriptor)
