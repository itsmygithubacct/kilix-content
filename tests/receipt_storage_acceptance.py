"""Guest-side receipt-store power-loss acceptance worker.

This is an operator-run acceptance helper, not a unit test.  The host runner
starts one operation, waits until this process reaches an exact filesystem
boundary, and removes power from the whole disposable guest.  On the next
boot, ``verify`` proves that recovery never turns an incomplete transaction
into authorization.

Run this file through the project's locked uv environment.  The synthetic
receipt authority it imports lives in ``tests/`` and is absent from the wheel.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import socket
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from kilix_content import (
    AssetSpec,
    DurabilityUnknown,
    LicenseDecision,
    ReceiptError,
    ReceiptMissing,
    ReconcileResult,
    ReleaseContext,
)
import kilix_content.receipt as receipt_module
from tests.receipt_store_support import open_test_store


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/contracts/valid/asset-mirrored.json"
LICENSE_TEXT = b"Exact storage acceptance license bytes.\n"
FORMAT_BYTES = b'{"schema":"kilix.install.license-store/v1"}\n'
EXPECTED_COUNTS = {
    "format": {"fsync": 2, "link": 1, "unlink": 1},
    "record": {"fsync": 5, "link": 2, "unlink": 3},
}


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def objects() -> tuple[AssetSpec, ReleaseContext, LicenseDecision]:
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["licenses"][0]["text_sha256"] = hashlib.sha256(LICENSE_TEXT).hexdigest()
    spec = AssetSpec.from_mapping(record)
    release = ReleaseContext.from_catalog(
        "0.2.1", b'{"release":"0.2.1","assets":"storage-acceptance"}\n'
    )
    requirement = spec.licenses[0]
    decision = LicenseDecision.from_mapping(
        {
            "artifact_ids": [spec.asset_id],
            "decision_class": requirement.decision,
            "kind": "decision",
            "license_id": requirement.license_id,
            "license_text_sha256": requirement.text_sha256,
            "outcome": "record",
            "presenter": "kilix-storage-acceptance",
            "release": release.release_id,
            "schema": "kilix.install.license/v1",
        }
    )
    return spec, release, decision


def require_safe_root(root: Path) -> Path:
    root = Path(os.path.abspath(os.fspath(root)))
    configured_temporary = os.environ.get("TMPDIR")
    if configured_temporary:
        if not os.path.isabs(configured_temporary):
            raise ValueError("TMPDIR must be absolute for storage acceptance")
        # ``tempfile`` probes candidate directories by creating a file.  That
        # probe is intentionally expected to fail on several filesystems this
        # acceptance helper exercises, so pin its already operator-supplied
        # absolute root instead of silently falling back to /tmp.
        tempfile.tempdir = configured_temporary
    temporary = Path(os.path.realpath(tempfile.gettempdir()))
    resolved_parent = root.parent.resolve()
    if temporary != resolved_parent and temporary not in resolved_parent.parents:
        raise ValueError("acceptance root must remain below the configured temp root")
    if root == temporary or not root.name:
        raise ValueError("acceptance root must be a distinct child")
    return root


def prepare_format(root: Path) -> None:
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    descriptor = os.open(
        root / ".lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def prepare_record(root: Path) -> None:
    with open_test_store(str(root), clock=lambda: 1.25):
        pass


class BoundaryController:
    """Count receipt-module operations and stop at one requested boundary."""

    def __init__(
        self,
        scenario: str,
        operation: str,
        occurrence: int,
        boundary: str,
        port: int,
    ) -> None:
        self.scenario = scenario
        self.operation = operation
        self.occurrence = occurrence
        self.boundary = boundary
        self.port = port
        self.counts = {"fsync": 0, "link": 0, "unlink": 0}
        self._fsync = os.fsync
        self._link = os.link
        self._unlink = os.unlink

    def _event(self, operation: str, boundary: str) -> None:
        if operation != self.operation or boundary != self.boundary:
            return
        if self.counts[operation] != self.occurrence:
            return
        payload = canonical(
            {
                "boundary": boundary,
                "counts": dict(self.counts),
                "occurrence": self.occurrence,
                "operation": operation,
                "pid": os.getpid(),
                "scenario": self.scenario,
                "schema": "kilix.content.receipt-power-boundary/v1",
            }
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen(1)
            connection, _address = server.accept()
            with connection:
                connection.sendall(payload)
        # The host removes whole-guest power after receiving the payload.  A
        # finite fallback makes a lost controller fail instead of continuing.
        time.sleep(300)
        raise RuntimeError("host did not remove guest power at the armed boundary")

    def fsync(self, descriptor: int) -> None:
        self.counts["fsync"] += 1
        self._event("fsync", "before")
        self._fsync(descriptor)
        self._event("fsync", "after")

    def link(self, *args: Any, **kwargs: Any) -> None:
        self.counts["link"] += 1
        self._event("link", "before")
        self._link(*args, **kwargs)
        self._event("link", "after")

    def unlink(self, *args: Any, **kwargs: Any) -> None:
        self.counts["unlink"] += 1
        self._event("unlink", "before")
        self._unlink(*args, **kwargs)
        self._event("unlink", "after")

    def install(self) -> None:
        receipt_module.os.fsync = self.fsync
        receipt_module.os.link = self.link
        receipt_module.os.unlink = self.unlink

    def restore(self) -> None:
        receipt_module.os.fsync = self._fsync
        receipt_module.os.link = self._link
        receipt_module.os.unlink = self._unlink


def arm(args: argparse.Namespace) -> int:
    root = require_safe_root(args.root)
    if root.exists():
        raise ValueError("armed acceptance root already exists")
    if args.operation not in EXPECTED_COUNTS[args.scenario]:
        raise ValueError("unsupported operation")
    maximum = EXPECTED_COUNTS[args.scenario][args.operation]
    if not 1 <= args.occurrence <= maximum:
        raise ValueError(f"occurrence must be between 1 and {maximum}")
    if args.scenario == "format":
        prepare_format(root)
    else:
        prepare_record(root)

    controller = BoundaryController(
        args.scenario,
        args.operation,
        args.occurrence,
        args.boundary,
        args.signal_port,
    )
    controller.install()
    try:
        if args.scenario == "format":
            with open_test_store(str(root), clock=lambda: 1.25):
                pass
        else:
            spec, release, decision = objects()
            with open_test_store(str(root), clock=lambda: 1.25) as store:
                store.record(decision, LICENSE_TEXT, release, [spec])
    finally:
        controller.restore()
    raise RuntimeError(
        "armed operation completed without reaching the requested boundary: "
        + json.dumps(controller.counts, sort_keys=True)
    )


def namespace(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not root.exists():
        return result
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        info = path.lstat()
        kind = "file" if stat.S_ISREG(info.st_mode) else "other"
        item: dict[str, Any] = {
            "kind": kind,
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "nlink": info.st_nlink,
            "size": info.st_size,
        }
        if kind == "file" and info.st_size <= 1024 * 1024:
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[path.name] = item
    return result


def assert_final_namespace(root: Path, authorized: bool) -> None:
    entries = namespace(root)
    if entries.get(".format", {}).get("sha256") != hashlib.sha256(
        FORMAT_BYTES
    ).hexdigest():
        raise AssertionError("format marker is missing or invalid after recovery")
    if ".pending" in entries or any(name.startswith(".tmp-") for name in entries):
        raise AssertionError("recovery left pending or temporary state")
    receipt_names = [
        name
        for name in entries
        if len(name) == 69 and name.endswith(".json")
    ]
    if len(receipt_names) != int(authorized):
        raise AssertionError("final receipt count does not match authorization state")
    for name, item in entries.items():
        expected_mode = "0700" if item["kind"] == "other" else "0600"
        if item["kind"] != "file" or item["mode"] != expected_mode or item["nlink"] != 1:
            raise AssertionError(f"unsafe final store object: {name}")


def verify(args: argparse.Namespace) -> int:
    root = require_safe_root(args.root)
    before = namespace(root)
    result: dict[str, Any] = {
        "before": before,
        "root": str(root),
        "scenario": args.scenario,
        "schema": "kilix.content.receipt-power-recovery/v1",
    }
    if args.scenario == "format":
        with open_test_store(str(root), clock=lambda: 1.25):
            pass
        authorized = False
        result["initial_authorization"] = "not-applicable"
        result["reconciliation"] = "not-applicable"
    else:
        spec, release, _decision = objects()
        with open_test_store(str(root), clock=lambda: 1.25) as store:
            try:
                verified = store.require_asset(spec, release)
            except DurabilityUnknown:
                initial = "pending-blocked"
                reconciliation = store.reconcile()
                if reconciliation.status not in ("aborted", "committed"):
                    raise AssertionError("pending recovery returned an invalid state")
                result["reconciliation"] = {
                    "key": reconciliation.key,
                    "status": reconciliation.status,
                }
                if reconciliation.status == "committed":
                    verified = store.require_asset(spec, release)
                    if len(verified) != 1:
                        raise AssertionError("committed receipt did not authorize exactly once")
                    authorized = True
                else:
                    try:
                        store.require_asset(spec, release)
                    except ReceiptMissing:
                        authorized = False
                    else:
                        raise AssertionError("aborted receipt unexpectedly authorized")
            except ReceiptMissing:
                initial = "missing"
                reconciliation = store.reconcile()
                if reconciliation != ReconcileResult("clean"):
                    raise AssertionError("missing state was not clean")
                result["reconciliation"] = {"key": None, "status": "clean"}
                authorized = False
            else:
                if len(verified) != 1:
                    raise AssertionError("durable receipt did not authorize exactly once")
                initial = "authorized"
                reconciliation = store.reconcile()
                if reconciliation != ReconcileResult("clean"):
                    raise AssertionError("authorized state was not clean")
                result["reconciliation"] = {"key": None, "status": "clean"}
                authorized = True
            result["initial_authorization"] = initial
    assert_final_namespace(root, authorized)
    result["authorized_after_recovery"] = authorized
    result["after"] = namespace(root)
    result["status"] = "pass"
    print(json.dumps(result, sort_keys=True))
    return 0


def initialize(args: argparse.Namespace) -> int:
    root = require_safe_root(args.root)
    if root.exists():
        raise ValueError("initialization root already exists")
    with open_test_store(str(root), clock=lambda: 1.25):
        pass
    print(
        json.dumps(
            {
                "namespace": namespace(root),
                "root": str(root),
                "schema": "kilix.content.receipt-storage-initialize/v1",
                "status": "pass",
            },
            sort_keys=True,
        )
    )
    return 0


def exception_errnos(error: BaseException) -> list[int]:
    result = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "errno", None)
        if isinstance(value, int):
            result.append(value)
        current = current.__cause__ or current.__context__
    return result


def attempt(args: argparse.Namespace) -> int:
    root = require_safe_root(args.root)
    spec, release, decision = objects()
    store = None
    try:
        store = open_test_store(str(root), clock=lambda: 1.25)
        store.record(decision, LICENSE_TEXT, release, [spec])
    except Exception as exc:  # acceptance records the normalized and OS errors
        errnos = exception_errnos(exc)
        expected = getattr(errno, args.expected_errno)
        if expected not in errnos:
            raise AssertionError(
                f"expected {args.expected_errno} ({expected}), observed {errnos}"
            ) from exc
        authorization = "store-open-failed"
        if store is not None:
            try:
                store.require_asset(spec, release)
            except DurabilityUnknown:
                authorization = "pending-blocked"
            except ReceiptMissing:
                authorization = "missing"
            except ReceiptError as authorization_error:
                authorization = f"refused-{type(authorization_error).__name__}"
            else:
                raise AssertionError("failed storage operation unexpectedly authorized")
        print(
            json.dumps(
                {
                    "authorization": authorization,
                    "errnos": errnos,
                    "exception": type(exc).__name__,
                    "expected_errno": args.expected_errno,
                    "namespace": namespace(root),
                    "root": str(root),
                    "schema": "kilix.content.receipt-storage-error/v1",
                    "status": "pass",
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        if store is not None:
            store.close()
    raise AssertionError("storage-error attempt unexpectedly succeeded")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser()
    subcommands = command.add_subparsers(dest="command", required=True)
    armed = subcommands.add_parser("arm")
    armed.add_argument("--scenario", choices=tuple(EXPECTED_COUNTS), required=True)
    armed.add_argument("--root", type=Path, required=True)
    armed.add_argument("--operation", choices=("fsync", "link", "unlink"), required=True)
    armed.add_argument("--occurrence", type=int, required=True)
    armed.add_argument("--boundary", choices=("before", "after"), required=True)
    armed.add_argument("--signal-port", type=int, default=9001)
    armed.set_defaults(function=arm)

    checked = subcommands.add_parser("verify")
    checked.add_argument("--scenario", choices=tuple(EXPECTED_COUNTS), required=True)
    checked.add_argument("--root", type=Path, required=True)
    checked.set_defaults(function=verify)

    initialized = subcommands.add_parser("initialize")
    initialized.add_argument("--root", type=Path, required=True)
    initialized.set_defaults(function=initialize)

    attempted = subcommands.add_parser("attempt")
    attempted.add_argument("--root", type=Path, required=True)
    attempted.add_argument(
        "--expected-errno",
        choices=("EDQUOT", "EIO", "EINVAL", "ENOSPC", "EROFS"),
        required=True,
    )
    attempted.set_defaults(function=attempt)
    return command


def main() -> int:
    args = parser().parse_args()
    return args.function(args)


if __name__ == "__main__":
    raise SystemExit(main())
