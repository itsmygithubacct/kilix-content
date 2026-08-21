"""Closed system, toolchain, sandbox, and license profile semantics."""

from __future__ import annotations

import re
from typing import Any

from .u1_core import (
    ENV_RE,
    digest_without,
    refuse,
    require_array,
    require_digest,
    require_id,
    require_keys,
    require_object,
    require_s64,
    require_sorted_unique,
    require_text,
)


ARCH_RE = re.compile(r"^(?:amd64|arm64|riscv64)$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}$")
ABSOLUTE_PATH_RE = re.compile(r"^/(?:[a-zA-Z0-9._+-]+/)*[a-zA-Z0-9._+-]+$")
RESOURCE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
SNAPSHOT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
ALLOWED_ENVIRONMENT = {
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "SOURCE_DATE_EPOCH",
    "TZ",
}
REQUIRED_IPC_DENIALS = {
    "ipc",
    "memfd_create",
    "memfd_secret",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedsend",
    "mq_unlink",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
}
DEVICE_ENDPOINTS = ("/dev/null", "/dev/random", "/dev/urandom", "/dev/zero")


def _absolute_path(value: Any) -> str:
    path = require_text(value, ABSOLUTE_PATH_RE, maximum=256)
    if "//" in path or "/./" in path or "/../" in path or path.endswith(("/.", "/..")):
        refuse("absolute path is not canonical")
    return path


def _resource_path(value: Any) -> str:
    path = require_text(value, RESOURCE_PATH_RE, maximum=256)
    if "//" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        refuse("resource path is not canonical")
    return path


def _validate_snapshot(value: Any) -> None:
    snapshot = require_object(value)
    require_keys(
        snapshot,
        required=("distribution", "suite", "timestamp", "release_sha256"),
    )
    if snapshot["distribution"] != "debian" or snapshot["suite"] != "trixie":
        refuse("release snapshot distribution is not frozen")
    require_text(snapshot["timestamp"], SNAPSHOT_RE, maximum=16)
    require_digest(snapshot["release_sha256"])


def _validate_package(value: Any, *, architecture: str) -> None:
    package = require_object(value)
    require_keys(package, required=("name", "version", "architecture", "sha256"))
    require_text(package["name"], PACKAGE_RE, maximum=128)
    require_text(package["version"], VERSION_RE, maximum=256)
    if require_text(package["architecture"], ARCH_RE, maximum=16) != architecture:
        refuse("package architecture diverges from its profile")
    require_digest(package["sha256"])


def _validate_packages(value: Any, *, architecture: str) -> list[dict[str, Any]]:
    packages = require_array(value, maximum=1_024)
    names: set[str] = set()
    for raw_package in packages:
        package = require_object(raw_package)
        _validate_package(package, architecture=architecture)
        if package["name"] in names:
            refuse("profile package is duplicated")
        names.add(package["name"])
    require_sorted_unique(packages)
    return packages


def validate_system_requirements(value: Any) -> None:
    profile = require_object(value)
    require_keys(
        profile,
        required=(
            "schema",
            "id",
            "release_snapshot",
            "architecture",
            "packages",
            "manifest_sha256",
        ),
    )
    if profile["schema"] != "kilix.content.system-requirements/v1":
        refuse("system requirement schema is not frozen")
    require_id(profile["id"])
    _validate_snapshot(profile["release_snapshot"])
    architecture = require_text(profile["architecture"], ARCH_RE, maximum=16)
    _validate_packages(profile["packages"], architecture=architecture)
    require_digest(profile["manifest_sha256"])
    if profile["manifest_sha256"] != digest_without(
        "system-requirements", profile, ("manifest_sha256",)
    ):
        refuse("system requirement manifest digest is inconsistent")


def _validate_file_inventory(value: Any, *, executable: bool) -> list[dict[str, Any]]:
    entries = require_array(value, maximum=2_048)
    paths: set[str] = set()
    for raw_entry in entries:
        entry = require_object(raw_entry)
        require_keys(entry, required=("path", "mode", "sha256"))
        path = _absolute_path(entry["path"])
        if path in paths:
            refuse("toolchain file path is duplicated")
        paths.add(path)
        mode = require_s64(entry["mode"])
        permitted = {0o555, 0o755} if executable else {0o444, 0o644}
        if mode not in permitted:
            refuse("toolchain file mode is outside the frozen enum")
        require_digest(entry["sha256"])
    require_sorted_unique(entries)
    return entries


def validate_toolchain_profile(value: Any) -> None:
    profile = require_object(value)
    require_keys(
        profile,
        required=(
            "schema",
            "id",
            "release_snapshot",
            "architecture",
            "packages",
            "executables",
            "libraries",
            "entrypoints",
            "offline_python",
            "environment",
            "abi",
            "profile_sha256",
        ),
    )
    if profile["schema"] != "kilix.content.toolchain-profile/v1":
        refuse("toolchain profile schema is not frozen")
    require_id(profile["id"])
    _validate_snapshot(profile["release_snapshot"])
    architecture = require_text(profile["architecture"], ARCH_RE, maximum=16)
    _validate_packages(profile["packages"], architecture=architecture)
    executables = _validate_file_inventory(profile["executables"], executable=True)
    _validate_file_inventory(profile["libraries"], executable=False)
    executable_paths = {item["path"] for item in executables}

    entrypoints = require_array(profile["entrypoints"], minimum=1, maximum=128)
    entrypoint_ids: set[str] = set()
    for raw_entrypoint in entrypoints:
        entrypoint = require_object(raw_entrypoint)
        require_keys(entrypoint, required=("id", "executable", "argv"))
        identifier = require_id(entrypoint["id"])
        if identifier in entrypoint_ids:
            refuse("toolchain entrypoint is duplicated")
        entrypoint_ids.add(identifier)
        if _absolute_path(entrypoint["executable"]) not in executable_paths:
            refuse("toolchain entrypoint executable is not inventoried")
        argv = require_array(entrypoint["argv"], maximum=64)
        for argument in argv:
            require_text(argument, maximum=1_024, allow_empty=True)
    require_sorted_unique(entrypoints)

    python = require_object(profile["offline_python"])
    require_keys(
        python,
        required=(
            "enabled",
            "python_version",
            "python_sha256",
            "uv_version",
            "uv_sha256",
            "project_sha256",
            "lock_sha256",
            "wheels",
        ),
    )
    if type(python["enabled"]) is not bool:
        refuse("offline Python enablement is not boolean")
    require_text(python["python_version"], VERSION_RE, maximum=64)
    require_text(python["uv_version"], VERSION_RE, maximum=64)
    for name in ("python_sha256", "uv_sha256", "project_sha256", "lock_sha256"):
        require_digest(python[name])
    wheels = require_array(python["wheels"], maximum=1_024)
    wheel_names: set[str] = set()
    for raw_wheel in wheels:
        wheel = require_object(raw_wheel)
        require_keys(wheel, required=("name", "version", "sha256"))
        name = require_text(wheel["name"], PACKAGE_RE, maximum=128)
        if name in wheel_names:
            refuse("offline Python wheel is duplicated")
        wheel_names.add(name)
        require_text(wheel["version"], VERSION_RE, maximum=256)
        require_digest(wheel["sha256"])
    require_sorted_unique(wheels)
    if python["enabled"] and not wheels:
        refuse("enabled offline Python profile lacks wheel authority")
    if not python["enabled"] and wheels:
        refuse("disabled offline Python profile contains wheel authority")

    environment = require_array(
        profile["environment"], maximum=len(ALLOWED_ENVIRONMENT)
    )
    names: set[str] = set()
    for raw_assignment in environment:
        assignment = require_object(raw_assignment)
        require_keys(assignment, required=("name", "value"))
        name = require_text(assignment["name"], ENV_RE, maximum=64)
        if name not in ALLOWED_ENVIRONMENT or name in names:
            refuse("toolchain environment name is not frozen or is duplicated")
        names.add(name)
        require_text(assignment["value"], maximum=4_096, allow_empty=True)
    require_sorted_unique(environment)

    abi = require_object(profile["abi"])
    require_keys(
        abi,
        required=(
            "libc",
            "libc_version",
            "kernel_abi",
            "machine",
            "endianness",
            "pointer_bits",
        ),
    )
    if abi["libc"] != "glibc" or abi["endianness"] not in {"big", "little"}:
        refuse("toolchain ABI is outside the frozen enum")
    require_text(abi["libc_version"], VERSION_RE, maximum=64)
    require_text(abi["kernel_abi"], VERSION_RE, maximum=64)
    if require_text(abi["machine"], ARCH_RE, maximum=16) != architecture:
        refuse("toolchain ABI architecture diverges from its profile")
    if abi["pointer_bits"] != 64:
        refuse("toolchain ABI pointer width is not frozen")

    require_digest(profile["profile_sha256"])
    if profile["profile_sha256"] != digest_without(
        "toolchain-profile", profile, ("profile_sha256",)
    ):
        refuse("toolchain profile digest is inconsistent")


def validate_sandbox_profile(value: Any) -> None:
    profile = require_object(value)
    require_keys(
        profile,
        required=(
            "schema",
            "id",
            "mounts",
            "namespaces",
            "capabilities",
            "seccomp",
            "devices",
            "proc_policy",
            "resource_limit_shape",
            "quota_backend",
            "profile_sha256",
        ),
    )
    if profile["schema"] != "kilix.content.sandbox-profile/v1":
        refuse("sandbox profile schema is not frozen")
    require_id(profile["id"])

    mounts = require_array(profile["mounts"], minimum=1, maximum=128)
    targets: set[str] = set()
    for raw_mount in mounts:
        mount = require_object(raw_mount)
        require_keys(
            mount,
            required=(
                "source_role",
                "target",
                "kind",
                "read_only",
                "noexec",
                "nosuid",
                "nodev",
            ),
        )
        require_id(mount["source_role"])
        target = _absolute_path(mount["target"])
        if target in targets:
            refuse("sandbox mount target is duplicated")
        targets.add(target)
        if mount["kind"] not in {"bind", "proc", "tmpfs"}:
            refuse("sandbox mount kind is outside the frozen enum")
        if any(
            type(mount[name]) is not bool
            for name in ("read_only", "noexec", "nosuid", "nodev")
        ):
            refuse("sandbox mount flag is not boolean")
    require_sorted_unique(mounts)

    namespaces = require_object(profile["namespaces"])
    require_keys(namespaces, required=("user", "mount", "pid", "network", "ipc"))
    if set(namespaces.values()) != {"fresh"}:
        refuse("sandbox namespace profile is not fully fresh")
    capabilities = require_array(profile["capabilities"], maximum=0)
    if capabilities:
        refuse("sandbox retains Linux capabilities")

    seccomp = require_object(profile["seccomp"])
    require_keys(
        seccomp, required=("architecture", "default_action", "denied_syscalls")
    )
    require_text(seccomp["architecture"], ARCH_RE, maximum=16)
    if seccomp["default_action"] != "allow-except-denied":
        refuse("sandbox seccomp default action is not frozen")
    denied = require_array(
        seccomp["denied_syscalls"], minimum=len(REQUIRED_IPC_DENIALS), maximum=256
    )
    for syscall in denied:
        require_id(syscall)
    if denied != sorted(denied) or len(denied) != len(set(denied)):
        refuse("sandbox syscall deny list is not sorted unique data")
    if not REQUIRED_IPC_DENIALS <= set(denied):
        refuse("sandbox syscall deny list omits kernel IPC")

    devices = require_array(profile["devices"], minimum=4, maximum=4)
    for device in devices:
        _absolute_path(device)
    if tuple(devices) != DEVICE_ENDPOINTS:
        refuse("sandbox device set is not the exact non-storage set")
    proc = require_object(profile["proc_policy"])
    require_keys(
        proc,
        required=("mounted", "read_only", "hidepid", "mqueue_absent", "shm_absent"),
    )
    if proc != {
        "mounted": True,
        "read_only": True,
        "hidepid": 2,
        "mqueue_absent": True,
        "shm_absent": True,
    }:
        refuse("sandbox proc and IPC-mount policy is not frozen")

    limits = require_object(profile["resource_limit_shape"])
    require_keys(
        limits, required=("memory", "pids", "cpu", "tmpfs_bytes", "tmpfs_inodes")
    )
    if set(limits.values()) != {"capacity-policy"}:
        refuse("sandbox resource limit source is not capacity authority")
    quota = require_object(profile["quota_backend"])
    require_keys(quota, required=("kind", "enforced", "filesystem_accounting"))
    if quota != {
        "kind": "tmpfs-cgroup-v2",
        "enforced": True,
        "filesystem_accounting": True,
    }:
        refuse("sandbox quota backend is not frozen")

    require_digest(profile["profile_sha256"])
    if profile["profile_sha256"] != digest_without(
        "sandbox-profile", profile, ("profile_sha256",)
    ):
        refuse("sandbox profile digest is inconsistent")


def validate_license_manifest(value: Any) -> None:
    manifest = require_object(value)
    require_keys(manifest, required=("schema", "release_id", "licenses"))
    if manifest["schema"] != "kilix.content.license-manifest/v1":
        refuse("license manifest schema is not frozen")
    require_id(manifest["release_id"])
    licenses = require_array(manifest["licenses"], minimum=1, maximum=256)
    identifiers: set[str] = set()
    paths: set[str] = set()
    for raw_license in licenses:
        license_record = require_object(raw_license)
        require_keys(license_record, required=("id", "path", "text_sha256", "decision"))
        identifier = require_id(license_record["id"])
        path = _resource_path(license_record["path"])
        if identifier in identifiers or path in paths:
            refuse("license manifest identity or path is duplicated")
        identifiers.add(identifier)
        paths.add(path)
        require_digest(license_record["text_sha256"])
        if license_record["decision"] not in {
            "affirmative",
            "informational",
            "restricted",
            "user-supplied",
        }:
            refuse("license manifest decision is outside the frozen enum")
    require_sorted_unique(licenses)


__all__ = [
    "ALLOWED_ENVIRONMENT",
    "DEVICE_ENDPOINTS",
    "REQUIRED_IPC_DENIALS",
    "validate_license_manifest",
    "validate_sandbox_profile",
    "validate_system_requirements",
    "validate_toolchain_profile",
]
