#!/usr/bin/env python3
"""Mechanically repin the R16 authority to an exact corrected gate commit."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from typing import Any, NoReturn


PROJECT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = PROJECT / "authority" / "f100-u1-r16" / "authority.json"
GATE_PATH = PROJECT / "tests" / "check_reproducible_build.py"
VERIFIER_PATH = PROJECT / "tools" / "f100_u1_r16_external_authority.py"
AUDITS = (
    ("sdist_container_audit", "sdist", "container"),
    ("assert_sdist_enumerator_agreement", "sdist", "enumerator"),
    ("sdist_payload_audit", "sdist", "payload"),
    ("sdist_member_closure_audit", "sdist", "closure"),
    ("sdist_generated_metadata_audit", "sdist", "generated-metadata"),
    ("wheel_container_audit", "wheel", "container"),
    ("wheel_archive_audit", "wheel", "archive"),
    ("record_audit", "wheel", "record"),
    ("resource_audit", "wheel", "resource-authority"),
    ("wheel_resource_audit", "wheel", "resource"),
    ("wheel_module_source_audit", "wheel", "module"),
    ("installed_wheel_audit", "wheel", "installed"),
)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def load_verifier():
    spec = importlib.util.spec_from_file_location("r16_external_authority", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        fail(f"cannot load verifier: {VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def object_id(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        fail(f"{label} is not a full lowercase Git object id")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-tree", required=True)
    arguments = parser.parse_args()
    commit = object_id(arguments.candidate_commit, "--candidate-commit")
    tree_id = object_id(arguments.candidate_tree, "--candidate-tree")

    verifier = load_verifier()
    gate_raw = GATE_PATH.read_bytes()
    tree = ast.parse(gate_raw)
    functions = verifier.module_functions(tree)
    rows = verifier.registry_rows(tree)
    inventory = verifier.derive_call_inventory(tree, "main")
    registry_digest = verifier.sha256_bytes(
        verifier.canonical_json(rows, newline=False)
    )
    gate_digest = verifier.sha256_bytes(gate_raw)

    authority: dict[str, Any] = json.loads(AUTHORITY_PATH.read_bytes())
    authority["candidate"] = {
        "commit": commit,
        "gate_path": "tests/check_reproducible_build.py",
        "gate_sha256": gate_digest,
        "tree": tree_id,
    }

    roles = {
        item["function"]: item["role"]
        for item in authority["history"]["protected_definitions"]
    }
    authority["history"]["protected_definitions"] = [
        {
            "definition_sha256": verifier.ast_sha256(functions[name]),
            "function": name,
            "role": roles[name],
        }
        for name in roles
    ]
    authority["history"]["required_prefix"] = rows
    snapshot = {
        "commit": commit,
        "gate_sha256": gate_digest,
        "registry_sha256": registry_digest,
        "row_count": len(rows),
        "row_ids": [row["id"] for row in rows],
        "tree": tree_id,
    }
    snapshots = authority["history"]["snapshots"]
    if snapshots[-1]["commit"] == commit:
        snapshots[-1] = snapshot
    else:
        snapshots.append(snapshot)

    frozen_audits = []
    for function_name, family, kind in AUDITS:
        if function_name not in functions:
            fail(f"audit definition is absent: {function_name}")
        callee = verifier.structural_ast_dump(
            ast.Name(id=function_name, ctx=ast.Load())
        )
        sites = sorted(
            item["structural_sha256"]
            for item in inventory
            if item["owner"] == "main" and item["callee"] == callee
        )
        if not sites:
            fail(f"audit has no structural main site: {function_name}")
        frozen_audits.append(
            {
                "definition_sha256": verifier.ast_sha256(functions[function_name]),
                "family": family,
                "function": function_name,
                "kind": kind,
                "main_call_site_sha256s": sites,
            }
        )
    authority["production_population"] = {
        "audit_count": len(frozen_audits),
        "audits": frozen_audits,
        "entrypoint": "main",
        "enumeration_rule": (
            "Starting only at the documented main function, form a fixed point over "
            "every top-level module function called directly or referenced in any call "
            "argument or callback. In every reached owner, enumerate every syntactic "
            "call, including calls inside lambdas and nested function bodies. Identify "
            "each site by owner plus attribute-free AST plus duplicate occurrence, never "
            "by a line number. Freeze this call-site population before reading decorators "
            "or registry rows; then classify the twelve independently enumerated "
            "artifact-audit definitions and compare their family/kind pairs with the "
            "registry."
        ),
        "reachable_call_site_count": len(inventory),
        "reachable_call_sites_sha256": verifier.sha256_bytes(
            verifier.canonical_json(inventory)
        ),
        "reachable_owner_count": len({item["owner"] for item in inventory}),
        "registry_pair_count": len(
            {(row["artifact_family"], row["audit_kind"]) for row in rows}
        ),
    }
    verifier_raw = VERIFIER_PATH.read_bytes()
    authority["implementation"]["verifier"] = {
        "bytes": len(verifier_raw),
        "path": VERIFIER_PATH.relative_to(PROJECT).as_posix(),
        "sha256": hashlib.sha256(verifier_raw).hexdigest(),
    }
    AUTHORITY_PATH.write_bytes(verifier.canonical_json(authority))
    print(hashlib.sha256(AUTHORITY_PATH.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
