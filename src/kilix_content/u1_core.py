"""Pure canonical primitives for the F100 Step-6 U1 contract freeze.

This module deliberately has no filesystem, process, network, clock, recovery,
or authorization side effects.  It accepts already supplied bytes and values,
and returns deterministic bytes, digests, or validation errors.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, NoReturn


class U1ContractError(ValueError):
    """A value is outside the frozen U1 language."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        bounded = message[:160]
        super().__init__(bounded)
        self.code = (
            code or "U1_" + re.sub(r"[^A-Z0-9]+", "_", bounded.upper()).strip("_")[:60]
        )


MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 65_536
MAX_JSON_TOKENS = 131_072
MAX_TOTAL_PROPERTIES = 65_536
MAX_TOTAL_ARRAY_ITEMS = 65_536
MAX_TOTAL_STRING_BYTES = 4 * 1024 * 1024
MAX_TOTAL_STRING_CODEPOINTS = 2 * 1024 * 1024
MAX_ARRAY_ITEMS = 4_096
MAX_OBJECT_PROPERTIES = 4_096
MAX_STRING_BYTES = 262_144
MAX_STRING_CODEPOINTS = 65_536
MAX_INTEGER_TOKEN_DIGITS = 20
S64_MAX = 2**63 - 1
U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1
ZERO_DIGEST = "0" * 64

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
RELATIVE_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,255}$")

DIGEST_DOMAINS: dict[str, bytes] = {
    "catalog-v5": b"kilix-content catalog/v5\0",
    "source-identity": b"kilix-content source-identity/v1\0",
    "install-record": b"kilix-content install-record/v5\0",
    "install-authority": b"kilix-content install-authority/v1\0",
    "output": b"kilix-content output-binding/v1\0",
    "authorization-v2": b"kilix-content authorization/v2\0",
    "system-requirements": b"kilix-content system-requirements/v1\0",
    "toolchain-profile": b"kilix-content toolchain-profile/v1\0",
    "sandbox-profile": b"kilix-content sandbox-profile/v1\0",
    "license-manifest": b"kilix-content license-manifest/v1\0",
    "filesystem-capacity-v2": b"kilix-content filesystem capacity/v2\0",
    "capacity-policy": b"kilix-content capacity policy/v2\0",
    "capacity-generation": b"kilix-content capacity generation/v2\0",
    "release-proof": b"kilix-content release proof/v2\0",
    "retention-intent": b"kilix-content retention intent/v1\0",
    "retention-component": b"kilix-content retention component/v1\0",
    "retention-envelope": b"kilix-content retention envelope/v1\0",
    "retention-marker": b"kilix-content retention marker/v1\0",
    "retention-marker-semantic": b"kilix-content retention marker semantic/v1\0",
    "retention-relation": b"kilix-content retention relation/v1\0",
    "retention-relation-semantic": b"kilix-content retention relation semantic/v1\0",
    "retention-journal": b"kilix-content retention journal/v1\0",
    "retention-capacity": b"kilix-content retention capacity/v1\0",
    "retention-counts": b"kilix-content retention counts/v1\0",
    "retention-accounted": b"kilix-content retention accounted/v1\0",
    "retention-handoff": b"kilix-content retention handoff/v1\0",
    "retention-child-set": b"kilix-content retention child-set/v1\0",
    "retention-logical-state": b"kilix-content retention logical state/v1\0",
    "retention-physical-state": b"kilix-content retention physical state/v1\0",
    "retention-physical-envelope": b"kilix-content retention physical envelope/v1\0",
    "retention-descriptor": b"kilix-content retention descriptor/v1\0",
    "retention-absence-evidence": b"kilix-content retention absence evidence/v1\0",
    "recovery-vector": b"kilix-content recovery vector/v1\0",
}


def refuse(message: str) -> NoReturn:
    """Raise a fixed, non-secret-bearing contract error."""
    raise U1ContractError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON key")
        result[key] = value
    return result


def _constant(_value: str) -> NoReturn:
    refuse("non-standard JSON constant")


def _float(_value: str) -> NoReturn:
    refuse("floating-point JSON value is forbidden")


def _integer(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > MAX_INTEGER_TOKEN_DIGITS:
        refuse("JSON integer is outside the token bound")
    try:
        value = int(token, 10)
    except ValueError as exc:  # defensive; json normally filters syntax first
        raise U1ContractError("JSON integer is invalid") from exc
    if value < -S64_MAX - 1 or value > U64_MAX:
        refuse("JSON integer is outside the representation bound")
    return value


def _safe_text(value: str, *, key: bool = False) -> None:
    limit = 256 if key else MAX_STRING_CODEPOINTS
    if len(value) > limit or unicodedata.normalize("NFC", value) != value:
        refuse("JSON text is outside the canonical Unicode bound")
    for character in value:
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            refuse("JSON text contains a forbidden Unicode code point")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        refuse("JSON text is outside the canonical Unicode bound")


def walk_json(value: Any) -> None:
    """Apply aggregate canonical bounds to an in-memory JSON value."""
    nodes = 0
    properties = 0
    array_items = 0
    string_bytes = 0
    string_codepoints = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal array_items, nodes, properties, string_bytes, string_codepoints
        nodes += 1
        if nodes > MAX_JSON_NODES:
            refuse("JSON value exceeds the aggregate node bound")
        if depth > MAX_JSON_DEPTH:
            refuse("JSON value exceeds the nesting bound")
        if type(item) is dict:
            if len(item) > MAX_OBJECT_PROPERTIES:
                refuse("JSON object exceeds the property bound")
            properties += len(item)
            if properties > MAX_TOTAL_PROPERTIES:
                refuse("JSON value exceeds the aggregate property bound")
            for key, child in item.items():
                if type(key) is not str:
                    refuse("JSON object key is not text")
                _safe_text(key, key=True)
                string_bytes += len(key.encode("utf-8"))
                string_codepoints += len(key)
                walk(child, depth + 1)
            return
        if type(item) is list:
            if len(item) > MAX_ARRAY_ITEMS:
                refuse("JSON array exceeds the item bound")
            array_items += len(item)
            if array_items > MAX_TOTAL_ARRAY_ITEMS:
                refuse("JSON value exceeds the aggregate array-item bound")
            for child in item:
                walk(child, depth + 1)
            return
        if type(item) is str:
            _safe_text(item)
            string_bytes += len(item.encode("utf-8"))
            string_codepoints += len(item)
            if (
                string_bytes > MAX_TOTAL_STRING_BYTES
                or string_codepoints > MAX_TOTAL_STRING_CODEPOINTS
            ):
                refuse("JSON value exceeds the aggregate string bound")
            return
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if item < -S64_MAX - 1 or item > U64_MAX:
                refuse("JSON integer is outside the representation bound")
            return
        refuse("JSON value contains a forbidden scalar type")

    walk(value, 0)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole compact, sorted, NFC, UTF-8 U1 JSON representation."""
    walk_json(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError, RecursionError) as exc:
        raise U1ContractError("JSON value cannot be canonically encoded") from exc
    if len(encoded) > MAX_JSON_BYTES:
        refuse("canonical JSON exceeds the encoded-byte bound")
    return encoded


def _enforce_json_token_budget(text: str) -> None:
    """Count JSON lexical tokens without first materializing the value graph."""
    tokens = 0
    index = 0
    length = len(text)

    def consume() -> None:
        nonlocal tokens
        tokens += 1
        if tokens > MAX_JSON_TOKENS:
            refuse("JSON input exceeds the lexical token bound")

    while index < length:
        character = text[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character in "{}[],:":
            consume()
            index += 1
            continue
        if character == '"':
            consume()
            index += 1
            while index < length:
                if text[index] == '"':
                    index += 1
                    break
                if text[index] == "\\":
                    # Escape sequences are separate lexical work even though
                    # they remain inside one JSON string token.  Counting
                    # them also makes every consecutive budget boundary
                    # representable by canonical JSON.
                    consume()
                    index += 2
                else:
                    index += 1
            continue
        if character in "-0123456789":
            consume()
            index += 1
            while index < length and text[index] not in ' \t\r\n{}[],:"':
                index += 1
            continue
        matched = False
        for literal in ("true", "false", "null"):
            if text.startswith(literal, index):
                consume()
                index += len(literal)
                matched = True
                break
        if matched:
            continue
        consume()
        index += 1


def parse_json_bytes(data: bytes) -> Any:
    """Parse bounded canonical JSON with duplicate and lexical-token limits."""
    if type(data) is not bytes or not data or len(data) > MAX_JSON_BYTES:
        refuse("JSON input is outside the encoded-byte bound")
    try:
        text = data.decode("utf-8")
        _enforce_json_token_budget(text)
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
            parse_int=_integer,
        )
    except U1ContractError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise U1ContractError("JSON input is not valid bounded UTF-8 JSON") from exc
    walk_json(value)
    if data != canonical_json_bytes(value):
        refuse("JSON input is not the canonical byte representation")
    return value


def canonical_digest(domain: str, value: Any) -> str:
    """Internal digest dispatcher; production callers use typed wrappers."""
    prefix = DIGEST_DOMAINS.get(domain)
    if prefix is None:
        refuse("unknown digest domain")
    return hashlib.sha256(prefix + canonical_json_bytes(value)).hexdigest()


def catalog_digest(value: Any) -> str:
    return canonical_digest("catalog-v5", value)


def source_identity_digest(value: Any) -> str:
    return canonical_digest("source-identity", value)


def install_record_digest(value: Any) -> str:
    return canonical_digest("install-record", value)


def install_authority_digest(value: Any) -> str:
    return canonical_digest("install-authority", value)


def output_binding_digest(value: Any) -> str:
    return canonical_digest("output", value)


def authorization_record_digest(value: Any) -> str:
    return digest_without("authorization-v2", require_object(value), ("record_sha256",))


def capacity_policy_digest(value: Any) -> str:
    return canonical_digest("capacity-policy", value)


def capacity_generation_digest(value: Any) -> str:
    return canonical_digest("capacity-generation", value)


def release_proof_digest(value: Any) -> str:
    return canonical_digest("release-proof", value)


def retention_intent_digest(value: Any) -> str:
    return canonical_digest("retention-intent", value)


def retention_component_digest(value: Any) -> str:
    return canonical_digest("retention-component", value)


def retention_envelope_digest(value: Any) -> str:
    return digest_without(
        "retention-envelope", require_object(value), ("envelope_sha256",)
    )


def retention_component_envelope_digest(
    intent_identity: Mapping[str, Any], entries: Sequence[Any]
) -> str:
    """Bind envelope entries to the acyclic intent identity."""
    return canonical_digest(
        "retention-envelope",
        {
            "schema": "kilix.content.retention-envelope/v1",
            "intent_identity": dict(intent_identity),
            "entries": list(entries),
        },
    )


def retention_marker_digest(value: Any) -> str:
    return canonical_digest("retention-marker", value)


def _retention_semantic_core(value: Any) -> dict[str, Any]:
    record = require_object(value)
    return {
        key: child
        for key, child in record.items()
        if key not in {"descriptor", "semantic_payload_sha256"}
    }


def retention_marker_semantic_bytes(value: Any) -> bytes:
    return canonical_json_bytes(_retention_semantic_core(value))


def retention_marker_semantic_digest(value: Any) -> str:
    return hashlib.sha256(
        DIGEST_DOMAINS["retention-marker-semantic"]
        + retention_marker_semantic_bytes(value)
    ).hexdigest()


def retention_marker_content_digest(value: Any) -> str:
    return hashlib.sha256(retention_marker_semantic_bytes(value)).hexdigest()


def retention_relation_digest(value: Any) -> str:
    return canonical_digest("retention-relation", value)


def retention_relation_semantic_bytes(value: Any) -> bytes:
    return canonical_json_bytes(_retention_semantic_core(value))


def retention_relation_semantic_digest(value: Any) -> str:
    return hashlib.sha256(
        DIGEST_DOMAINS["retention-relation-semantic"]
        + retention_relation_semantic_bytes(value)
    ).hexdigest()


def retention_relation_content_digest(value: Any) -> str:
    return hashlib.sha256(retention_relation_semantic_bytes(value)).hexdigest()


def retention_accounted_digest(value: Any) -> str:
    return canonical_digest("retention-accounted", value)


def retention_handoff_digest(value: Any) -> str:
    return canonical_digest("retention-handoff", value)


def retention_logical_state_digest(value: Any) -> str:
    return canonical_digest("retention-logical-state", value)


def retention_physical_state_digest(value: Any) -> str:
    return canonical_digest("retention-physical-state", value)


def retention_physical_envelope_digest(value: Any) -> str:
    return digest_without(
        "retention-physical-envelope", require_object(value), ("envelope_sha256",)
    )


def retention_descriptor_digest(value: Any) -> str:
    return digest_without(
        "retention-descriptor",
        require_object(value),
        ("descriptor_identity_sha256",),
    )


def retention_absence_evidence_digest(value: Any) -> str:
    return digest_without(
        "retention-absence-evidence", require_object(value), ("sha256",)
    )


def transaction_generation_digest(value: Any) -> str:
    return canonical_digest("retention-journal", value)


def digest_without(
    domain: str, value: Mapping[str, Any], excluded: Iterable[str]
) -> str:
    """Hash a closed semantic core after explicitly removing envelope fields."""
    excluded_set = set(excluded)
    core = {key: child for key, child in value.items() if key not in excluded_set}
    return canonical_digest(domain, core)


def require_object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        refuse("value must be an object")
    return value


def require_keys(
    value: Mapping[str, Any], *, required: Iterable[str], optional: Iterable[str] = ()
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    if set(value) != required_set | (
        set(value) & set(optional)
    ) or not required_set <= set(value):
        refuse("object fields do not match the frozen shape")
    if not set(value) <= allowed:
        refuse("object fields do not match the frozen shape")


def require_text(
    value: Any,
    pattern: re.Pattern[str] | None = None,
    *,
    maximum: int = 256,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or (not value and not allow_empty)
        or len(value) > maximum
    ):
        refuse("text field is outside the frozen bound")
    _safe_text(value)
    if pattern is not None and pattern.fullmatch(value) is None:
        refuse("text field is outside the frozen grammar")
    return value


def require_id(value: Any) -> str:
    return require_text(value, ID_RE, maximum=64)


def require_digest(value: Any) -> str:
    return require_text(value, HEX64_RE, maximum=64)


def require_relative_path(value: Any) -> str:
    path = require_text(value, RELATIVE_PATH_RE, maximum=256)
    if any(part in {"", ".", ".."} for part in path.split("/")):
        refuse("relative path is not canonical")
    return path


def require_s64(value: Any, *, minimum: int = 0, positive: bool = False) -> int:
    lower = 1 if positive else minimum
    if type(value) is not int or value < lower or value > S64_MAX:
        refuse("integer field is outside the signed-64 bound")
    return value


def require_u32(value: Any, *, nonzero: bool = False) -> int:
    lower = 1 if nonzero else 0
    if type(value) is not int or value < lower or value > U32_MAX:
        refuse("integer field is outside the unsigned-32 bound")
    return value


def require_u64(value: Any, *, nonzero: bool = False) -> int:
    lower = 1 if nonzero else 0
    if type(value) is not int or value < lower or value > U64_MAX:
        refuse("integer field is outside the unsigned-64 bound")
    return value


def require_array(
    value: Any, *, minimum: int = 0, maximum: int = MAX_ARRAY_ITEMS
) -> list[Any]:
    if type(value) is not list or len(value) < minimum or len(value) > maximum:
        refuse("array field is outside the frozen bound")
    return value


def require_sorted_unique(values: Sequence[Any]) -> None:
    encoded = [canonical_json_bytes(item) for item in values]
    if encoded != sorted(encoded) or len(encoded) != len(set(encoded)):
        refuse("array is not canonical sorted unique data")


def checked_add(values: Iterable[int]) -> int:
    result = 0
    for value in values:
        require_s64(value)
        if result > S64_MAX - value:
            refuse("checked addition overflow")
        result += value
    return result


def checked_mul(left: int, right: int) -> int:
    require_s64(left)
    require_s64(right)
    if left and right > S64_MAX // left:
        refuse("checked multiplication overflow")
    return left * right


def checked_round_up(value: int, alignment: int) -> int:
    require_s64(value)
    require_s64(alignment, positive=True)
    remainder = value % alignment
    return value if remainder == 0 else checked_add((value, alignment - remainder))


def _length_delimited(parts: Iterable[bytes]) -> bytes:
    result = bytearray()
    for part in parts:
        if len(part) > U32_MAX:
            refuse("length-delimited field is outside the unsigned-32 bound")
        result.extend(struct.pack(">I", len(part)))
        result.extend(part)
    return bytes(result)


def filesystem_key_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the exact R7 capacity-v2 filesystem-key preimage bytes."""
    root = require_object(value)
    require_keys(
        root,
        required=(
            "boot_id",
            "filesystem_magic",
            "filesystem_type_utf8",
            "st_dev_major",
            "st_dev_minor",
            "statfs_fsid_word_0",
            "statfs_fsid_word_1",
        ),
    )
    boot_id = require_text(root["boot_id"], HEX32_RE, maximum=32)
    if boot_id == "0" * 32:
        refuse("filesystem identity is zero")
    magic = require_u64(root["filesystem_magic"], nonzero=True)
    filesystem_type = require_text(
        root["filesystem_type_utf8"],
        re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}$"),
        maximum=32,
    )
    major = require_u32(root["st_dev_major"])
    minor = require_u32(root["st_dev_minor"])
    fsid_0 = require_u64(root["statfs_fsid_word_0"])
    fsid_1 = require_u64(root["statfs_fsid_word_1"])
    if fsid_0 == 0 and fsid_1 == 0:
        refuse("filesystem identity is zero")
    payload = _length_delimited(
        (
            bytes.fromhex(boot_id),
            struct.pack(">Q", magic),
            filesystem_type.encode("utf-8"),
            struct.pack(">I", major),
            struct.pack(">I", minor),
            struct.pack(">Q", fsid_0),
            struct.pack(">Q", fsid_1),
        )
    )
    return DIGEST_DOMAINS["filesystem-capacity-v2"] + payload


def filesystem_key_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(filesystem_key_bytes(value)).hexdigest()


__all__ = [
    "DIGEST_DOMAINS",
    "ENV_RE",
    "HEX32_RE",
    "HEX40_RE",
    "HEX64_RE",
    "ID_RE",
    "MAX_ARRAY_ITEMS",
    "MAX_JSON_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_TOKENS",
    "MAX_OBJECT_PROPERTIES",
    "MAX_STRING_BYTES",
    "MAX_STRING_CODEPOINTS",
    "MAX_TOTAL_ARRAY_ITEMS",
    "MAX_TOTAL_PROPERTIES",
    "MAX_TOTAL_STRING_BYTES",
    "MAX_TOTAL_STRING_CODEPOINTS",
    "RELATIVE_PATH_RE",
    "S64_MAX",
    "U1ContractError",
    "U32_MAX",
    "U64_MAX",
    "ZERO_DIGEST",
    "authorization_record_digest",
    "capacity_generation_digest",
    "capacity_policy_digest",
    "catalog_digest",
    "canonical_digest",
    "canonical_json_bytes",
    "checked_add",
    "checked_mul",
    "checked_round_up",
    "digest_without",
    "filesystem_key_bytes",
    "filesystem_key_digest",
    "install_authority_digest",
    "install_record_digest",
    "output_binding_digest",
    "parse_json_bytes",
    "refuse",
    "require_array",
    "require_digest",
    "require_id",
    "require_keys",
    "require_object",
    "require_relative_path",
    "require_s64",
    "require_sorted_unique",
    "require_text",
    "require_u32",
    "require_u64",
    "release_proof_digest",
    "retention_accounted_digest",
    "retention_absence_evidence_digest",
    "retention_component_digest",
    "retention_component_envelope_digest",
    "retention_descriptor_digest",
    "retention_envelope_digest",
    "retention_handoff_digest",
    "retention_intent_digest",
    "retention_logical_state_digest",
    "retention_marker_digest",
    "retention_marker_content_digest",
    "retention_marker_semantic_bytes",
    "retention_marker_semantic_digest",
    "retention_physical_envelope_digest",
    "retention_physical_state_digest",
    "retention_relation_digest",
    "retention_relation_content_digest",
    "retention_relation_semantic_bytes",
    "retention_relation_semantic_digest",
    "source_identity_digest",
    "transaction_generation_digest",
    "walk_json",
]
