#!/usr/bin/env python3
"""Accumulate R16-16 mutation accounting from externally authorized events.

This module is deliberately a leaf.  It does not import the release gate, own
the effect/presentation authority, or emit gate events.  Serial integration is
responsible for supplying an authority file frozen outside the candidate and
for wiring observed gate events into this accumulator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, NoReturn


AUTHORITY_SCHEMA = "kilix.content.f100-u1-r16-16-accounting-authority/v1"
EVENTS_SCHEMA = "kilix.content.f100-u1-r16-16-accounting-events/v1"
RESULT_SCHEMA = "kilix.content.f100-u1-r16-16-accounting-result/v1"
MAX_AUTHORITY_BYTES = 64 * 1024
MAX_EVENTS_BYTES = 1024 * 1024
MAX_EVENTS = 4096
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AccountingRefusal(ValueError):
    """A stable, machine-readable refusal from the R16-16 leaf."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class FamilyAuthority:
    family: str
    effect_ids: tuple[str, ...]
    presentation_ids: tuple[str, ...]
    byte_identity_group: str


@dataclass(frozen=True)
class AccountingAuthority:
    sha256: str
    families: tuple[FamilyAuthority, ...]


@dataclass(frozen=True)
class MutationEvent:
    family: str
    effect_id: str
    presentation_id: str
    artifact_sha256: str


def refuse(code: str) -> NoReturn:
    raise AccountingRefusal(code)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _closed_object(value: Any, keys: set[str], subject: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        refuse(f"COUNT_{subject}_OBJECT_NOT_CLOSED")
    return value


def _identifier(value: Any, subject: str) -> str:
    if type(value) is not str or IDENTIFIER.fullmatch(value) is None:
        refuse(f"COUNT_{subject}_ID_INVALID")
    return value


def _digest(value: Any, subject: str) -> str:
    if type(value) is not str or DIGEST.fullmatch(value) is None:
        refuse(f"COUNT_{subject}_DIGEST_INVALID")
    return value


def _unique_sorted_identifiers(value: Any, subject: str) -> tuple[str, ...]:
    if type(value) is not list or not value:
        refuse(f"COUNT_{subject}_LIST_INVALID")
    items = tuple(_identifier(item, subject) for item in value)
    if len(set(items)) != len(items):
        refuse(f"COUNT_{subject}_DUPLICATE")
    if items != tuple(sorted(items)):
        refuse(f"COUNT_{subject}_NOT_SORTED")
    return items


def _decode_json(raw: bytes, *, subject: str, maximum: int) -> Any:
    if not raw or len(raw) > maximum:
        refuse(f"COUNT_{subject}_SIZE_INVALID")

    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                refuse(f"COUNT_{subject}_DUPLICATE_JSON_KEY:{key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=closed_pairs,
            parse_constant=lambda token: refuse(
                f"COUNT_{subject}_NONFINITE_NUMBER:{token}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f"COUNT_{subject}_JSON_INVALID:{type(error).__name__}")
    if raw != canonical_json(value):
        refuse(f"COUNT_{subject}_JSON_NONCANONICAL")
    return value


def load_authority(
    path: Path, expected_sha256: str, candidate_root: Path
) -> AccountingAuthority:
    expected = _digest(expected_sha256, "AUTHORITY_EXPECTED")
    resolved_authority = path.resolve(strict=True)
    resolved_candidate = candidate_root.resolve(strict=True)
    if not resolved_candidate.is_dir():
        refuse("COUNT_CANDIDATE_ROOT_NOT_DIRECTORY")
    if resolved_authority.is_relative_to(resolved_candidate):
        refuse("COUNT_AUTHORITY_INSIDE_CANDIDATE")
    raw = resolved_authority.read_bytes()
    observed = sha256(raw)
    if observed != expected:
        refuse(f"COUNT_AUTHORITY_DIGEST_MISMATCH:{observed}")
    value = _decode_json(raw, subject="AUTHORITY", maximum=MAX_AUTHORITY_BYTES)
    root = _closed_object(value, {"schema", "families"}, "AUTHORITY")
    if root["schema"] != AUTHORITY_SCHEMA:
        refuse("COUNT_AUTHORITY_SCHEMA_INVALID")
    if type(root["families"]) is not list or not root["families"]:
        refuse("COUNT_AUTHORITY_FAMILIES_INVALID")

    families: list[FamilyAuthority] = []
    for value in root["families"]:
        row = _closed_object(
            value,
            {"byte_identity_group", "effect_ids", "id", "presentation_ids"},
            "AUTHORITY_FAMILY",
        )
        families.append(
            FamilyAuthority(
                family=_identifier(row["id"], "AUTHORITY_FAMILY"),
                effect_ids=_unique_sorted_identifiers(
                    row["effect_ids"], "AUTHORITY_EFFECT"
                ),
                presentation_ids=_unique_sorted_identifiers(
                    row["presentation_ids"], "AUTHORITY_PRESENTATION"
                ),
                byte_identity_group=_identifier(
                    row["byte_identity_group"], "AUTHORITY_BYTE_GROUP"
                ),
            )
        )
    family_ids = [family.family for family in families]
    if family_ids != sorted(family_ids):
        refuse("COUNT_AUTHORITY_FAMILIES_NOT_SORTED")
    if len(set(family_ids)) != len(family_ids):
        refuse("COUNT_AUTHORITY_FAMILY_DUPLICATE")
    effects = [effect for family in families for effect in family.effect_ids]
    if len(set(effects)) != len(effects):
        refuse("COUNT_AUTHORITY_EFFECT_CROSS_FAMILY_DUPLICATE")
    presentations = [
        presentation
        for family in families
        for presentation in family.presentation_ids
    ]
    if len(set(presentations)) != len(presentations):
        refuse("COUNT_AUTHORITY_PRESENTATION_CROSS_FAMILY_DUPLICATE")
    groups = {family.byte_identity_group for family in families}
    if len(groups) != len(families):
        refuse("COUNT_AUTHORITY_BYTE_GROUP_DUPLICATE")
    return AccountingAuthority(observed, tuple(families))


def load_events(path: Path, authority_sha256: str) -> tuple[MutationEvent, ...]:
    authority_digest = _digest(authority_sha256, "EVENT_AUTHORITY")
    raw = path.read_bytes()
    value = _decode_json(raw, subject="EVENTS", maximum=MAX_EVENTS_BYTES)
    root = _closed_object(
        value, {"authority_sha256", "events", "schema"}, "EVENTS"
    )
    if root["schema"] != EVENTS_SCHEMA:
        refuse("COUNT_EVENTS_SCHEMA_INVALID")
    if root["authority_sha256"] != authority_digest:
        refuse("COUNT_EVENTS_AUTHORITY_MISMATCH")
    if type(root["events"]) is not list or len(root["events"]) > MAX_EVENTS:
        refuse("COUNT_EVENTS_LIST_INVALID")
    events: list[MutationEvent] = []
    for value in root["events"]:
        row = _closed_object(
            value,
            {"artifact_sha256", "effect_id", "family", "presentation_id"},
            "EVENT",
        )
        events.append(
            MutationEvent(
                family=_identifier(row["family"], "EVENT_FAMILY"),
                effect_id=_identifier(row["effect_id"], "EVENT_EFFECT"),
                presentation_id=_identifier(
                    row["presentation_id"], "EVENT_PRESENTATION"
                ),
                artifact_sha256=_digest(row["artifact_sha256"], "EVENT_ARTIFACT"),
            )
        )
    return tuple(events)


def _member(family: str, identifier: str) -> dict[str, str]:
    return {"family": family, "id": identifier}


def accumulate(
    authority: AccountingAuthority, events: Iterable[MutationEvent]
) -> dict[str, Any]:
    """Validate events and return four independently projected populations."""
    observed = tuple(events)
    families = {row.family: row for row in authority.families}
    effect_family = {
        effect: row.family for row in authority.families for effect in row.effect_ids
    }
    presentation_family = {
        presentation: row.family
        for row in authority.families
        for presentation in row.presentation_ids
    }

    for event in observed:
        if event.family not in families:
            refuse(f"COUNT_UNEXPECTED_FAMILY:{event.family}")
        if event.effect_id not in effect_family:
            refuse(f"COUNT_UNEXPECTED_EFFECT:{event.effect_id}")
        if effect_family[event.effect_id] != event.family:
            refuse(f"COUNT_EFFECT_FAMILY_MISMATCH:{event.effect_id}")
        if event.presentation_id not in presentation_family:
            refuse(f"COUNT_UNEXPECTED_PRESENTATION:{event.presentation_id}")
        if presentation_family[event.presentation_id] != event.family:
            refuse(
                f"COUNT_PRESENTATION_FAMILY_MISMATCH:{event.presentation_id}"
            )

    seen_effects = {event.effect_id for event in observed}
    for effect in sorted(set(effect_family) - seen_effects):
        refuse(f"COUNT_MISSING_EFFECT:{effect}")
    seen_presentations = {event.presentation_id for event in observed}
    for presentation in sorted(set(presentation_family) - seen_presentations):
        refuse(f"COUNT_MISSING_PRESENTATION:{presentation}")

    expected_invocations = {
        (row.family, effect, presentation)
        for row in authority.families
        for effect in row.effect_ids
        for presentation in row.presentation_ids
    }
    invocation_counter = Counter(
        (event.family, event.effect_id, event.presentation_id) for event in observed
    )
    missing_invocations = sorted(expected_invocations - set(invocation_counter))
    if missing_invocations:
        family, effect, presentation = missing_invocations[0]
        refuse(f"COUNT_MISSING_INVOCATION:{family}:{effect}:{presentation}")
    duplicate_invocations = sorted(
        invocation for invocation, count in invocation_counter.items() if count != 1
    )
    if duplicate_invocations:
        family, effect, presentation = duplicate_invocations[0]
        refuse(f"COUNT_DUPLICATE_INVOCATION:{family}:{effect}:{presentation}")

    presentation_digests: dict[str, set[str]] = defaultdict(set)
    for event in observed:
        presentation_digests[event.presentation_id].add(event.artifact_sha256)
    for presentation, digests in sorted(presentation_digests.items()):
        if len(digests) != 1:
            refuse(f"COUNT_PRESENTATION_DIGEST_AMBIGUOUS:{presentation}")

    group_digests: dict[str, set[str]] = defaultdict(set)
    for row in authority.families:
        for presentation in row.presentation_ids:
            group_digests[row.byte_identity_group].update(
                presentation_digests[presentation]
            )
    for group, digests in sorted(group_digests.items()):
        if len(digests) != 1:
            refuse(f"COUNT_BYTE_IDENTITY_MISMATCH:{group}")
    digest_groups: dict[str, list[str]] = defaultdict(list)
    for group, digests in group_digests.items():
        digest_groups[next(iter(digests))].append(group)
    collisions = [groups for groups in digest_groups.values() if len(groups) != 1]
    if collisions:
        refuse("COUNT_BYTE_IDENTITY_COLLISION:" + ",".join(sorted(collisions[0])))

    invocation_members = [
        {
            "artifact_sha256": event.artifact_sha256,
            "effect_id": event.effect_id,
            "family": event.family,
            "presentation_id": event.presentation_id,
        }
        for event in sorted(
            observed,
            key=lambda item: (
                item.family,
                item.effect_id,
                item.presentation_id,
                item.artifact_sha256,
            ),
        )
    ]
    effect_members = [
        _member(row.family, effect)
        for row in authority.families
        for effect in row.effect_ids
    ]
    presentation_members = [
        {
            "artifact_sha256": next(iter(presentation_digests[presentation])),
            "family": row.family,
            "id": presentation,
        }
        for row in authority.families
        for presentation in row.presentation_ids
    ]
    byte_members = [
        {"group": group, "sha256": next(iter(digests))}
        for group, digests in sorted(group_digests.items())
    ]
    family_derivation = [
        {
            "effect_count": len(row.effect_ids),
            "family": row.family,
            "invocation_count": len(row.effect_ids) * len(row.presentation_ids),
            "presentation_count": len(row.presentation_ids),
        }
        for row in authority.families
    ]
    expected_effects = len(effect_family)
    expected_presentations = len(presentation_family)
    expected_bytes = len(group_digests)
    expected_invocation_count = len(expected_invocations)

    return {
        "authority_sha256": authority.sha256,
        "derivation": {
            "families": family_derivation,
            "invocation_sum": expected_invocation_count,
        },
        "populations": {
            "mutation_invocations": {
                "count": len(invocation_members),
                "equal": len(invocation_members) == expected_invocation_count,
                "expected_count": expected_invocation_count,
                "members": invocation_members,
            },
            "presentations": {
                "count": len(presentation_members),
                "equal": len(presentation_members) == expected_presentations,
                "expected_count": expected_presentations,
                "members": presentation_members,
            },
            "shipped_byte_identities": {
                "count": len(byte_members),
                "equal": len(byte_members) == expected_bytes,
                "expected_count": expected_bytes,
                "members": byte_members,
            },
            "unique_effect_classes": {
                "count": len(effect_members),
                "equal": len(effect_members) == expected_effects,
                "expected_count": expected_effects,
                "members": effect_members,
            },
        },
        "schema": RESULT_SCHEMA,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        authority = load_authority(
            args.authority, args.authority_sha256, args.candidate_root
        )
        events = load_events(args.events, authority.sha256)
        result = accumulate(authority, events)
        if args.output.exists():
            refuse("COUNT_OUTPUT_ALREADY_EXISTS")
        args.output.write_bytes(canonical_json(result))
    except (AccountingRefusal, OSError) as error:
        code = error.code if isinstance(error, AccountingRefusal) else type(error).__name__
        print(f"R16_16_REFUSE:{code}", file=sys.stderr)
        return 2
    populations = result["populations"]
    print(
        "R16-16 leaf accounting: PASS "
        f"invocations={populations['mutation_invocations']['count']}/"
        f"{populations['mutation_invocations']['expected_count']} "
        f"effects={populations['unique_effect_classes']['count']}/"
        f"{populations['unique_effect_classes']['expected_count']} "
        f"presentations={populations['presentations']['count']}/"
        f"{populations['presentations']['expected_count']} "
        f"byte_identities={populations['shipped_byte_identities']['count']}/"
        f"{populations['shipped_byte_identities']['expected_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
