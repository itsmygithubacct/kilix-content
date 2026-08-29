#!/usr/bin/env python3
"""Observe R16 gate records through OD-20-compliant anonymous pipes.

Run this tool only from an external-authority export disjoint from the candidate.
It verifies the pinned candidate and authority before execution, launches the
exact default gate, validates both records directly from pipe bytes, and writes
one canonical result to stdout.  A later preservation copy is not an input to
the verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn, Sequence


RESULT_SCHEMA = "kilix.content.f100-u1-r16-pipe-observer-result/v1"
MAX_CHANNEL_BYTES = 1024 * 1024
MAX_GATE_OUTPUT_BYTES = 2 * 1024 * 1024
GATE_TERMINAL = b"reproducible offline build and package audit: PASS "


class ObserverRefusal(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def refuse(code: str) -> NoReturn:
    raise ObserverRefusal(code)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        refuse(f"OBSERVER_MODULE_UNAVAILABLE:{path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def decode_r16_14(raw: bytes, module: ModuleType) -> Any:
    if not raw or len(raw) > MAX_CHANNEL_BYTES:
        refuse("OBSERVER_R16_14_SIZE_INVALID")

    def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                refuse(f"OBSERVER_R16_14_DUPLICATE_KEY:{key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_pairs,
            parse_constant=lambda token: refuse(
                f"OBSERVER_R16_14_NONFINITE:{token}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        refuse(f"OBSERVER_R16_14_JSON_INVALID:{type(exc).__name__}")
    if raw != module.canonical_json_bytes(value):
        refuse("OBSERVER_R16_14_NONCANONICAL")
    return value


def _read_bounded(fd: int, label: str, result: dict[str, bytes], errors: list[str]) -> None:
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CHANNEL_BYTES:
                errors.append(f"OBSERVER_{label}_CHANNEL_OVERSIZED")
                return
            chunks.append(chunk)
        result[label] = b"".join(chunks)
    except OSError as exc:
        errors.append(f"OBSERVER_{label}_CHANNEL_READ:{exc.errno}")
    finally:
        os.close(fd)


def run_with_channels(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    authority_sha256: str,
) -> tuple[int, bytes, bytes, bytes]:
    r16_14_read, r16_14_write = os.pipe()
    r16_16_read, r16_16_write = os.pipe()
    observed: dict[str, bytes] = {}
    errors: list[str] = []
    readers = [
        threading.Thread(
            target=_read_bounded,
            args=(r16_14_read, "R16_14", observed, errors),
        ),
        threading.Thread(
            target=_read_bounded,
            args=(r16_16_read, "R16_16", observed, errors),
        ),
    ]
    for reader in readers:
        reader.start()
    child_environment = dict(environment)
    child_environment.update(
        {
            "KILIX_F100_R16_14_TRACE_FD": str(r16_14_write),
            "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256": authority_sha256,
            "KILIX_F100_R16_16_EVENTS_FD": str(r16_16_write),
        }
    )
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=child_environment,
            pass_fds=(r16_14_write, r16_16_write),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError:
        os.close(r16_14_write)
        os.close(r16_16_write)
        for reader in readers:
            reader.join()
        refuse("OBSERVER_GATE_LAUNCH_FAILED")
    os.close(r16_14_write)
    os.close(r16_16_write)
    gate_output, _ = process.communicate()
    for reader in readers:
        reader.join()
    if errors:
        refuse(errors[0])
    if len(gate_output) > MAX_GATE_OUTPUT_BYTES:
        refuse("OBSERVER_GATE_OUTPUT_OVERSIZED")
    return (
        process.returncode,
        gate_output,
        observed.get("R16_14", b""),
        observed.get("R16_16", b""),
    )


def observe(arguments: argparse.Namespace) -> dict[str, Any]:
    candidate_root = Path(arguments.candidate_root).resolve(strict=True)
    authority_root = Path(arguments.authority_root).resolve(strict=True)
    temporary_root = Path(arguments.tmpdir).resolve(strict=True)
    if not candidate_root.is_dir() or not authority_root.is_dir():
        refuse("OBSERVER_ROOT_NOT_DIRECTORY")
    if authority_root.is_relative_to(candidate_root) or candidate_root.is_relative_to(
        authority_root
    ):
        refuse("OBSERVER_ROOTS_NOT_DISJOINT")
    if temporary_root == Path("/tmp") or temporary_root.is_relative_to(Path("/tmp")):
        refuse("OBSERVER_TMPDIR_UNSAFE")

    tool_root = Path(__file__).resolve().parent
    verifier = load_module(
        "f100_u1_r16_pipe_external_verifier",
        tool_root / "f100_u1_r16_external_authority.py",
    )
    r16_14_tool = load_module(
        "f100_u1_r16_pipe_r16_14",
        tool_root / "r16_14" / "sdist_call_set.py",
    )
    accounting = load_module(
        "f100_u1_r16_pipe_r16_16",
        tool_root / "f100_u1_r16_16_accounting.py",
    )
    static_result = verifier.verify(
        argparse.Namespace(
            authority_root=str(authority_root),
            authority_sha256=arguments.authority_sha256,
            candidate_root=str(candidate_root),
        )
    )
    accounting_sha256 = static_result["r16_16"]["accounting_authority_sha256"]
    ledger = r16_14_tool.load_ledger(
        authority_root / "r16-14-sdist-call-ledger.json"
    )
    accounting_authority = accounting.load_authority(
        authority_root / "r16-16-accounting-authority.json",
        accounting_sha256,
        candidate_root,
    )

    environment = dict(os.environ)
    environment["TMPDIR"] = str(temporary_root)
    command = [
        arguments.uv,
        "run",
        "--locked",
        "--offline",
        "--all-groups",
        "python",
        str(candidate_root / "tests" / "check_reproducible_build.py"),
    ]
    returncode, gate_output, r16_14_raw, r16_16_raw = run_with_channels(
        command,
        cwd=candidate_root,
        environment=environment,
        authority_sha256=accounting_sha256,
    )
    if returncode != 0:
        refuse(f"OBSERVER_GATE_RETURN_CODE:{returncode}")
    nonempty_lines = [line for line in gate_output.splitlines() if line]
    terminals = [line for line in nonempty_lines if line.startswith(GATE_TERMINAL)]
    if len(terminals) != 1 or terminals[0] != nonempty_lines[-1]:
        refuse(f"OBSERVER_GATE_TERMINAL_INVALID:{len(terminals)}")

    r16_14_value = decode_r16_14(r16_14_raw, r16_14_tool)
    r16_14_result = r16_14_tool.verify_effect_trace(ledger, r16_14_value)
    r16_16_events = accounting.decode_events(r16_16_raw, accounting_sha256)
    r16_16_result = accounting.accumulate(accounting_authority, r16_16_events)
    populations = r16_16_result["populations"]
    return {
        "authority_sha256": static_result["authority_sha256"],
        "candidate_gate_sha256": static_result["candidate_gate_sha256"],
        "channels": {
            "accepted": 2,
            "expected": 2,
            "r16_14_sha256": sha256(r16_14_raw),
            "r16_16_sha256": sha256(r16_16_raw),
            "type": "anonymous-pipe",
        },
        "gate": {
            "output_bytes": len(gate_output),
            "output_sha256": sha256(gate_output),
            "returncode": returncode,
            "terminal_count": len(terminals),
        },
        "r16_14": r16_14_result,
        "r16_16": {
            "byte_identities": populations["shipped_byte_identities"]["count"],
            "effect_classes": populations["unique_effect_classes"]["count"],
            "mutation_invocations": populations["mutation_invocations"]["count"],
            "presentations": populations["presentations"]["count"],
        },
        "schema": RESULT_SCHEMA,
        "status": "VERIFIED_NOT_GRADED",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--authority-root", required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--tmpdir", required=True)
    parser.add_argument("--uv", default="uv")
    return parser


def main() -> int:
    try:
        result = observe(build_parser().parse_args())
    except (ObserverRefusal, OSError) as exc:
        code = exc.code if isinstance(exc, ObserverRefusal) else type(exc).__name__
        result = {"code": code, "schema": RESULT_SCHEMA, "status": "REFUSED"}
        sys.stdout.buffer.write(canonical_json(result))
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
