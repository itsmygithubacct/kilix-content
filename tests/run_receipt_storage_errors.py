"""Run real-filesystem receipt storage-error acceptance in a disposable VM.

The operator must run this as an unprivileged passwordless-sudo test account.
It creates only uniquely named image files, loop mounts, and one device-mapper
target below paths derived from ``--run-id``.  It never targets the guest root
device.  Python execution stays in the project's locked uv environment; the
test-only FUSE boundary uses explicitly pinned fusepy 3.0.1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
WORKER = REPO / "tests/receipt_storage_acceptance.py"
FUSE_HELPER = REPO / "tests/unsupported_dir_fsync_mount.py"
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
FUSE_LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libfuse.so.2")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    document = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    try:
        view = memoryview(document)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short acceptance-report write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def run(
    command: list[str],
    *,
    accepted: tuple[int, ...] = (0,),
    env: dict[str, str] | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    if process.returncode not in accepted:
        raise RuntimeError(
            f"command failed ({process.returncode}): {command!r}\n"
            f"stdout={process.stdout!r}\nstderr={process.stderr!r}"
        )
    return process


def command_evidence(process: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "returncode": process.returncode,
        "stderr": process.stderr,
        "stdout": process.stdout,
    }


def worker(temp_root: Path, *arguments: str) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["TMPDIR"] = os.fspath(temp_root)
    environment["PYTHONPATH"] = f"{REPO / 'src'}:{REPO}"
    process = run([sys.executable, os.fspath(WORKER), *arguments], env=environment)
    lines = [line for line in process.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("receipt storage worker returned no JSON")
    result = json.loads(lines[-1])
    if result.get("status") != "pass":
        raise AssertionError(f"receipt storage worker did not pass: {result}")
    return result


def sudo(*arguments: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["sudo", "-n", *arguments], **kwargs)


def prepare_mountpoint(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"mountpoint already exists: {path}")
    sudo("/usr/bin/mkdir", "-m", "0700", os.fspath(path))


def initialize_mount(path: Path, account: str) -> dict[str, Any]:
    sudo("/usr/bin/chown", f"{account}:{account}", os.fspath(path))
    sudo("/usr/bin/chmod", "0700", os.fspath(path))
    return worker(path, "initialize", "--root", os.fspath(path / "state"))


def verify_mount(path: Path) -> dict[str, Any]:
    return worker(
        path,
        "verify",
        "--scenario",
        "record",
        "--root",
        os.fspath(path / "state"),
    )


def case_enospc(workspace: Path, mounts: Path, account: str) -> dict[str, Any]:
    base = workspace / "enospc"
    mount = mounts.with_name(mounts.name + "-enospc")
    base.mkdir(mode=0o700)
    image = base / "ext4.img"
    run(["/usr/bin/truncate", "-s", "32M", os.fspath(image)])
    run(["/usr/sbin/mkfs.ext4", "-q", "-F", os.fspath(image)])
    prepare_mountpoint(mount)
    mounted = False
    try:
        sudo("/usr/bin/mount", "-o", "loop", os.fspath(image), os.fspath(mount))
        mounted = True
        initialized = initialize_mount(mount, account)
        filler = mount / "fill"
        first = run(
            [
                "/usr/bin/dd",
                "if=/dev/zero",
                f"of={filler}",
                "bs=1M",
                "status=none",
            ],
            accepted=(1,),
        )
        last = run(
            [
                "/usr/bin/dd",
                "if=/dev/zero",
                f"of={filler}",
                "bs=1",
                "oflag=append",
                "conv=notrunc",
                "status=none",
            ],
            accepted=(1,),
        )
        capacity = run(["/usr/bin/df", "-B1", os.fspath(mount)])
        failed = worker(
            mount,
            "attempt",
            "--root",
            os.fspath(mount / "state"),
            "--expected-errno",
            "ENOSPC",
        )
        filler.unlink()
        run(["/usr/bin/sync"])
        recovered = verify_mount(mount)
        return {
            "capacity_at_failure": capacity.stdout,
            "fill_errors": [command_evidence(first), command_evidence(last)],
            "initialization": initialized,
            "recovery": recovered,
            "refusal": failed,
            "status": "pass",
        }
    finally:
        if mounted:
            sudo("/usr/bin/umount", os.fspath(mount), accepted=(0, 32))


def case_edquot(workspace: Path, mounts: Path, account: str) -> dict[str, Any]:
    base = workspace / "edquot"
    mount = mounts.with_name(mounts.name + "-edquot")
    base.mkdir(mode=0o700)
    image = base / "ext4-quota.img"
    run(["/usr/bin/truncate", "-s", "64M", os.fspath(image)])
    run(["/usr/sbin/mkfs.ext4", "-q", "-F", "-O", "quota", os.fspath(image)])
    prepare_mountpoint(mount)
    mounted = False
    quota_set = False
    try:
        sudo(
            "/usr/bin/mount",
            "-o",
            "loop,usrquota",
            os.fspath(image),
            os.fspath(mount),
        )
        mounted = True
        initialized = initialize_mount(mount, account)
        # ``quotaon -p`` returns 2 when some quota classes are off even while
        # its output confirms that the user quota under test is on.
        state = sudo(
            "/usr/sbin/quotaon", "-p", os.fspath(mount), accepted=(0, 2)
        )
        if "user quota" not in state.stdout or " is on" not in state.stdout:
            raise AssertionError("the ext4 user quota is not active")
        sudo("/usr/sbin/setquota", "-u", account, "1", "1", "0", "0", os.fspath(mount))
        quota_set = True
        quota = run(["/usr/bin/quota", "-u", account, "-v"], accepted=(0, 1))
        failed = worker(
            mount,
            "attempt",
            "--root",
            os.fspath(mount / "state"),
            "--expected-errno",
            "EDQUOT",
        )
        sudo("/usr/sbin/setquota", "-u", account, "0", "0", "0", "0", os.fspath(mount))
        quota_set = False
        run(["/usr/bin/sync"])
        recovered = verify_mount(mount)
        return {
            "initialization": initialized,
            "quota": quota.stdout,
            "quota_state": state.stdout,
            "recovery": recovered,
            "refusal": failed,
            "status": "pass",
        }
    finally:
        if quota_set:
            sudo(
                "/usr/sbin/setquota",
                "-u",
                account,
                "0",
                "0",
                "0",
                "0",
                os.fspath(mount),
                accepted=(0, 1),
            )
        if mounted:
            sudo("/usr/bin/umount", os.fspath(mount), accepted=(0, 32))


def case_erofs(workspace: Path, mounts: Path, account: str) -> dict[str, Any]:
    base = workspace / "erofs"
    mount = mounts.with_name(mounts.name + "-erofs")
    base.mkdir(mode=0o700)
    image = base / "ext4.img"
    run(["/usr/bin/truncate", "-s", "32M", os.fspath(image)])
    run(["/usr/sbin/mkfs.ext4", "-q", "-F", os.fspath(image)])
    prepare_mountpoint(mount)
    mounted = False
    try:
        sudo("/usr/bin/mount", "-o", "loop,rw", os.fspath(image), os.fspath(mount))
        mounted = True
        initialized = initialize_mount(mount, account)
        sudo("/usr/bin/umount", os.fspath(mount))
        mounted = False
        sudo("/usr/bin/mount", "-o", "loop,ro", os.fspath(image), os.fspath(mount))
        mounted = True
        mount_fact = run(
            ["/usr/bin/findmnt", "-J", "-T", os.fspath(mount), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]
        )
        failed = worker(
            mount,
            "attempt",
            "--root",
            os.fspath(mount / "state"),
            "--expected-errno",
            "EROFS",
        )
        sudo("/usr/bin/umount", os.fspath(mount))
        mounted = False
        sudo("/usr/bin/mount", "-o", "loop,rw", os.fspath(image), os.fspath(mount))
        mounted = True
        recovered = verify_mount(mount)
        return {
            "initialization": initialized,
            "mount": json.loads(mount_fact.stdout),
            "recovery": recovered,
            "refusal": failed,
            "status": "pass",
        }
    finally:
        if mounted:
            sudo("/usr/bin/umount", os.fspath(mount), accepted=(0, 32))


def wait_for_fuse(mount: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(f"FUSE helper exited: {stdout!r} {stderr!r}")
        observed = run(
            ["/usr/bin/findmnt", "-n", "-T", os.fspath(mount), "-o", "FSTYPE"],
            accepted=(0, 1),
        )
        if observed.stdout.strip() == "fuse":
            return
        time.sleep(0.1)
    raise TimeoutError("FUSE helper did not mount")


def case_unsupported_fsync(workspace: Path) -> dict[str, Any]:
    if not FUSE_LIBRARY.is_file():
        raise RuntimeError("libfuse2t64 is required for the FUSE2 acceptance boundary")
    base = workspace / "unsupported-dir-fsync"
    backing = base / "backing"
    mount = base / "mount"
    backing.mkdir(mode=0o700, parents=True)
    mount.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    mount.mkdir(mode=0o700)
    initialized = worker(
        backing, "initialize", "--root", os.fspath(backing / "state")
    )
    environment = dict(os.environ)
    environment["FUSE_LIBRARY_PATH"] = os.fspath(FUSE_LIBRARY)
    process = subprocess.Popen(
        [
            "/usr/local/bin/uv",
            "run",
            "--no-project",
            "--with",
            "fusepy==3.0.1",
            "python",
            os.fspath(FUSE_HELPER),
            os.fspath(backing),
            os.fspath(mount),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    mounted = False
    try:
        wait_for_fuse(mount, process)
        mounted = True
        mount_fact = run(
            ["/usr/bin/findmnt", "-J", "-T", os.fspath(mount), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]
        )
        failed = worker(
            mount,
            "attempt",
            "--root",
            os.fspath(mount / "state"),
            "--expected-errno",
            "EINVAL",
        )
        run(["/usr/bin/fusermount3", "-u", os.fspath(mount)])
        mounted = False
        process.wait(timeout=10)
        recovered = verify_mount(backing)
        return {
            "fusepy": "3.0.1",
            "initialization": initialized,
            "mount": json.loads(mount_fact.stdout),
            "recovery": recovered,
            "refusal": failed,
            "status": "pass",
        }
    finally:
        if mounted:
            run(
                ["/usr/bin/fusermount3", "-u", os.fspath(mount)],
                accepted=(0, 1),
            )
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def case_eio(workspace: Path, mounts: Path, account: str, run_id: str) -> dict[str, Any]:
    base = workspace / "eio"
    mount = mounts.with_name(mounts.name + "-eio")
    base.mkdir(mode=0o700)
    image = base / "ext4.img"
    run(["/usr/bin/truncate", "-s", "64M", os.fspath(image)])
    prepare_mountpoint(mount)
    name = "f100_" + run_id.replace("-", "_") + "_eio"
    absent = sudo("/usr/sbin/dmsetup", "info", name, accepted=(0, 1, 4))
    if absent.returncode == 0:
        raise FileExistsError(f"device-mapper target already exists: {name}")
    loop = sudo("/usr/sbin/losetup", "--find", "--show", os.fspath(image)).stdout.strip()
    if not loop.startswith("/dev/loop"):
        raise RuntimeError(f"unexpected loop device: {loop!r}")
    sectors = sudo("/usr/sbin/blockdev", "--getsz", loop).stdout.strip()
    if not sectors.isdigit():
        raise RuntimeError("could not determine loop-device sectors")
    linear = f"0 {sectors} linear {loop} 0"
    error = f"0 {sectors} error"
    dm_created = False
    mounted = False
    error_active = False
    try:
        sudo("/usr/sbin/dmsetup", "create", name, "--table", linear)
        dm_created = True
        device = f"/dev/mapper/{name}"
        sudo("/usr/sbin/mkfs.ext4", "-q", "-F", device)
        sudo("/usr/bin/mount", "-o", "rw", device, os.fspath(mount))
        mounted = True
        initialized = initialize_mount(mount, account)
        run(["/usr/bin/sync"])
        sudo("/usr/sbin/dmsetup", "suspend", name)
        sudo("/usr/sbin/dmsetup", "load", name, "--table", error)
        sudo("/usr/sbin/dmsetup", "resume", name)
        error_active = True
        error_table = sudo("/usr/sbin/dmsetup", "table", name)
        failed = worker(
            mount,
            "attempt",
            "--root",
            os.fspath(mount / "state"),
            "--expected-errno",
            "EIO",
        )
        sudo("/usr/sbin/dmsetup", "suspend", "--noflush", "--nolockfs", name)
        sudo("/usr/sbin/dmsetup", "load", name, "--table", linear)
        sudo("/usr/sbin/dmsetup", "resume", name)
        error_active = False
        linear_table = sudo("/usr/sbin/dmsetup", "table", name)
        run(["/usr/bin/sync"], accepted=(0, 1))
        sudo("/usr/bin/umount", os.fspath(mount))
        mounted = False
        repaired = sudo("/usr/sbin/e2fsck", "-fy", device, accepted=(0, 1))
        sudo("/usr/bin/mount", "-o", "rw", device, os.fspath(mount))
        mounted = True
        recovered = verify_mount(mount)
        return {
            "error_table": error_table.stdout,
            "filesystem_check": command_evidence(repaired),
            "initialization": initialized,
            "linear_table": linear_table.stdout,
            "recovery": recovered,
            "refusal": failed,
            "status": "pass",
        }
    finally:
        if error_active:
            sudo(
                "/usr/sbin/dmsetup",
                "suspend",
                "--noflush",
                "--nolockfs",
                name,
                accepted=(0, 1),
            )
            sudo(
                "/usr/sbin/dmsetup", "load", name, "--table", linear, accepted=(0, 1)
            )
            sudo("/usr/sbin/dmsetup", "resume", name, accepted=(0, 1))
        if mounted:
            sudo("/usr/bin/umount", os.fspath(mount), accepted=(0, 32))
        if dm_created:
            sudo("/usr/sbin/dmsetup", "remove", name, accepted=(0, 1, 4))
        sudo("/usr/sbin/losetup", "-d", loop, accepted=(0, 1))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if RUN_ID.fullmatch(args.run_id) is None:
        parser.error("--run-id must be a bounded lowercase token")
    if os.geteuid() == 0:
        parser.error("run as the unprivileged disposable-guest account")
    sudo("/usr/bin/true")
    account = pwd.getpwuid(os.geteuid()).pw_name
    workspace = Path("/var/tmp/f100-r4-storage-errors") / args.run_id
    mounts = Path("/mnt") / f"f100-r4-storage-errors-{args.run_id}"
    if workspace.exists() or mounts.exists():
        parser.error("run-id paths already exist; choose a new run-id")
    workspace.mkdir(mode=0o700, parents=True)

    package_versions = run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${Package}=${Version}\\n",
            "e2fsprogs",
            "fuse3",
            "libfuse2t64",
            "quota",
        ]
    )
    mount_fact = run(
        ["/usr/bin/findmnt", "-J", "-T", "/var/tmp", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]
    )
    report: dict[str, Any] = {
        "candidate": {
            "model_sha256": sha256(REPO / "src/kilix_content/model.py"),
            "receipt_sha256": sha256(REPO / "src/kilix_content/receipt.py"),
            "runner_sha256": sha256(Path(__file__)),
            "worker_sha256": sha256(WORKER),
        },
        "cases": {},
        "completed_at": None,
        "environment": {
            "kernel": run(["/usr/bin/uname", "-r"]).stdout.strip(),
            "packages": package_versions.stdout.splitlines(),
            "temporary_mount": json.loads(mount_fact.stdout),
            "uv": run(["/usr/local/bin/uv", "--version"]).stdout.strip(),
        },
        "run_id": args.run_id,
        "schema": "kilix.content.receipt-storage-errors/v1",
        "started_at": now(),
        "status": "running",
    }
    atomic_json(args.output, report)
    case_functions = (
        ("ENOSPC", lambda: case_enospc(workspace, mounts, account)),
        ("EDQUOT", lambda: case_edquot(workspace, mounts, account)),
        ("EROFS", lambda: case_erofs(workspace, mounts, account)),
        ("unsupported-directory-fsync", lambda: case_unsupported_fsync(workspace)),
        ("EIO", lambda: case_eio(workspace, mounts, account, args.run_id)),
    )
    try:
        for name, function in case_functions:
            report["cases"][name] = function()
            atomic_json(args.output, report)
            print(f"PASS: {name}", flush=True)
    except Exception as exc:
        report["completed_at"] = now()
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["status"] = "fail"
        atomic_json(args.output, report)
        raise
    report["completed_at"] = now()
    report["status"] = "pass"
    atomic_json(args.output, report)
    print("PASS: 5/5 real storage-error cases", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
