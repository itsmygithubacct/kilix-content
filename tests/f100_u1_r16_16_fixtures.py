"""Test-only R16-16 authority, events, and causal control mutations.

These values exercise the frozen R15 32/12/5/2 topology.  They are candidate
fixtures, not the external freeze required for release acceptance.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


SDIST_EFFECTS = (
    "sdist.container.gzip-trailing",
    "sdist.enumerator.physical-directory-size",
    "sdist.member.permission",
    "sdist.payload.source-byte",
)
WHEEL_EFFECTS = (
    "wheel.archive.extra-member",
    "wheel.container.appended-zip",
    "wheel.container.prepend",
    "wheel.container.trailing",
    "wheel.installed.manifest",
    "wheel.module.source-byte",
    "wheel.record.self-row",
    "wheel.resource.byte",
)
SDIST_PRESENTATIONS = ("direct-sdist-1", "direct-sdist-2")
WHEEL_PRESENTATIONS = (
    "direct-wheel-1",
    "direct-wheel-2",
    "sdist-derived-wheel",
)
SDIST_SHA256 = "1" * 64
WHEEL_SHA256 = "2" * 64


def authority(schema: str) -> dict[str, Any]:
    return {
        "families": [
            {
                "byte_identity_group": "sdist-bytes",
                "effect_ids": list(SDIST_EFFECTS),
                "id": "sdist",
                "presentation_ids": list(SDIST_PRESENTATIONS),
            },
            {
                "byte_identity_group": "wheel-bytes",
                "effect_ids": list(WHEEL_EFFECTS),
                "id": "wheel",
                "presentation_ids": list(WHEEL_PRESENTATIONS),
            },
        ],
        "schema": schema,
    }


def events() -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for family, effects, presentations, artifact_sha256 in (
        ("sdist", SDIST_EFFECTS, SDIST_PRESENTATIONS, SDIST_SHA256),
        ("wheel", WHEEL_EFFECTS, WHEEL_PRESENTATIONS, WHEEL_SHA256),
    ):
        for effect in effects:
            for presentation in presentations:
                result.append(
                    {
                        "artifact_sha256": artifact_sha256,
                        "effect_id": effect,
                        "family": family,
                        "presentation_id": presentation,
                    }
                )
    return result


def control(case: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    mutated = deepcopy(events())
    details: dict[str, Any] = {"case": case, "mutation_fired": False}
    if case == "COUNT-DUP-INVOKE":
        mutated.append(deepcopy(mutated[0]))
        details["mutation_fired"] = len(mutated) == 33
    elif case == "COUNT-ALIAS-PRESENTATION":
        mutated[0]["presentation_id"] = "direct-sdist-1-alias"
        details["mutation_fired"] = mutated[0]["presentation_id"].endswith("-alias")
    elif case == "COUNT-NEW-BYTES":
        for event in mutated:
            if event["presentation_id"] == "direct-wheel-2":
                event["artifact_sha256"] = "3" * 64
        details["mutation_fired"] = sum(
            event["artifact_sha256"] == "3" * 64 for event in mutated
        ) == 8
    elif case == "COUNT-NEW-EFFECT":
        mutated[0]["effect_id"] = "sdist.unreviewed.effect"
        details["mutation_fired"] = mutated[0]["effect_id"].endswith(".effect")
    elif case == "COUNT-DELETE-EFFECT":
        target = SDIST_EFFECTS[0]
        mutated = [event for event in mutated if event["effect_id"] != target]
        details["mutation_fired"] = (
            len(mutated) == 30
            and all(event["effect_id"] != target for event in mutated)
        )
    elif case == "COUNT-DELETE-PRESENTATION":
        target = "direct-wheel-2"
        for event in mutated:
            if event["presentation_id"] == target:
                event["presentation_id"] = "direct-wheel-1"
        details["mutation_fired"] = (
            len(mutated) == 32
            and all(event["presentation_id"] != target for event in mutated)
        )
    elif case == "COUNT-SAME-DIGEST":
        details["mutation_fired"] = (
            len(
                {
                    event["artifact_sha256"]
                    for event in mutated
                    if event["family"] == "wheel"
                }
            )
            == 1
        )
    else:
        raise ValueError(f"unknown control: {case}")
    if not details["mutation_fired"]:
        raise AssertionError(f"control mutation did not fire: {case}")
    details["events_after"] = len(mutated)
    details["events_before"] = 32
    return mutated, details
