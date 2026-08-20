from __future__ import annotations

import errno
import fcntl
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

from kilix_content import (
    AcquisitionRequired,
    AssetFileSpec,
    AssetSpec,
    BindingMismatch,
    Catalog,
    ContentSpec,
    InstallError,
    Installer,
    LicenseDecision,
    ReceiptMissing,
    ReceiptStore,
    ReleaseContext,
    VerifiedInput,
)
from tests.receipt_store_support import open_test_store

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/contracts/valid/asset-user-supplied.json"
LICENSE_TEXT = b"Exact user-supplied acquisition test license.\n"


def load_record() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class UserSuppliedAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.installer = Installer(
            str(self.root / "content"), env={"PRIVATE_TOKEN": "do-not-inherit"}
        )
        self.release = ReleaseContext.from_catalog(
            "0.2.1", b'{"release":"0.2.1","catalog":"step-4-test"}\n'
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def spec(
        self,
        payload: bytes,
        *,
        asset_id: str = "game.user-data",
        version: str = "retail-1",
        output: bytes | None = None,
        output_path: str = "game/data.pak",
        conversion: bool = True,
        tool_id: str = "game.extractor",
        argv: tuple[str, ...] = ("extract", "{input}", "{output}"),
    ) -> AssetSpec:
        output = payload if output is None else output
        record = load_record()
        record["id"] = asset_id
        record["version"] = version
        record["files"] = [
            {
                "bytes": len(output),
                "path": output_path,
                "sha256": hashlib.sha256(output).hexdigest(),
            }
        ]
        record["sizes"]["installed_bytes"] = len(output)
        record["sizes"]["temporary_bytes"] = len(payload) + len(output)
        record["licenses"][0]["text_sha256"] = hashlib.sha256(
            LICENSE_TEXT
        ).hexdigest()
        record["source"]["input_bytes"] = len(payload)
        record["source"]["input_sha256"] = hashlib.sha256(payload).hexdigest()
        if conversion:
            record["source"]["conversion"] = {
                "argv": list(argv),
                "tool_asset_id": tool_id,
            }
        else:
            record["source"].pop("conversion", None)
        return AssetSpec.from_mapping(record)

    def input_file(
        self, payload: bytes, name: str = "user-input.bin"
    ) -> Path:
        path = self.root / name
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def tool(
        self,
        tool_id: str,
        script: str,
        *,
        binary: str = "converter",
    ) -> ContentSpec:
        repository = self.root / "tool-repositories" / tool_id
        repository.mkdir(parents=True)
        executable = repository / binary
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text(script, encoding="utf-8")
        executable.chmod(0o700)
        revision = self.commit_tool_repository(repository)
        return ContentSpec(
            content_id=tool_id,
            label="Test converter",
            kind="tool",
            icon="",
            description="Pinned test converter",
            source_type="git",
            repository=str(repository),
            ref=revision,
            binary=binary,
        )

    @staticmethod
    def commit_tool_repository(repository: Path) -> str:
        subprocess.run(
            ["git", "init", "--quiet"],
            cwd=repository,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "config", "user.email", "step4-tests@example.invalid"],
            cwd=repository,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Step 4 tests"],
            cwd=repository,
            check=True,
        )
        subprocess.run(["git", "add", "--all"], cwd=repository, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "Add pinned converter",
            ],
            cwd=repository,
            check=True,
        )
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def built_tool(self, tool_id: str, script: str) -> ContentSpec:
        repository = self.root / "tool-repositories" / tool_id
        repository.mkdir(parents=True)
        (repository / "converter-source").write_text(script, encoding="utf-8")
        (repository / "build.sh").write_text(
            """#!/bin/sh
set -eu
mkdir -p build
cp converter-source build/converter
chmod 700 build/converter
""",
            encoding="utf-8",
        )
        revision = self.commit_tool_repository(repository)
        return ContentSpec(
            content_id=tool_id,
            label="Test converter",
            kind="tool",
            icon="",
            description="Pinned test converter",
            source_type="git",
            repository=str(repository),
            ref=revision,
            binary="build/converter",
            build=("sh", "build.sh"),
        )

    def archive_tool(self, tool_id: str, script: str) -> ContentSpec:
        archive_path = self.root / "tool-archives" / f"{tool_id}.tar"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        body = script.encode("utf-8")
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo("converter")
            member.mode = 0o700
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        return ContentSpec(
            content_id=tool_id,
            label="Archive test converter",
            kind="tool",
            icon="",
            description="Pinned archive test converter",
            source_type="archive",
            urls=(archive_path.as_uri(),),
            sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            binary="converter",
        )

    @staticmethod
    def catalog(spec: AssetSpec, *tools: ContentSpec) -> Catalog:
        return Catalog(tools, schema_version=4, assets=(spec,))

    def authorize(
        self,
        store: ReceiptStore,
        spec: AssetSpec,
        input_path: Path,
    ) -> None:
        requirement = spec.licenses[0]
        decision = LicenseDecision.from_mapping(
            {
                "artifact_ids": [spec.asset_id],
                "decision_class": "user-supplied",
                "input_sha256": spec.input_sha256,
                "kind": "decision",
                "license_id": requirement.license_id,
                "license_text_sha256": requirement.text_sha256,
                "outcome": "supply",
                "presenter": "step-4-test",
                "release": self.release.release_id,
                "schema": "kilix.install.license/v1",
                "upstream_url": spec.official_url,
            }
        )
        with VerifiedInput.open(str(input_path)) as verified:
            store.record(
                decision,
                LICENSE_TEXT,
                self.release,
                [spec],
                verified_input=verified,
            )

    def open_store(self, name: str = "receipts") -> ReceiptStore:
        return open_test_store(str(self.root / name))

    def assert_no_selection_or_stage(self, spec: AssetSpec) -> None:
        destination = Path(self.installer.asset_destination(spec))
        self.assertFalse(destination.exists())
        parent = destination.parent
        if parent.exists():
            self.assertFalse(
                any(path.name.startswith(".asset-install-") for path in parent.iterdir())
            )

    def assert_process_stopped(self, pid: int, message: str) -> None:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split()[2]
            except (FileNotFoundError, ProcessLookupError):
                return
            if state in ("X", "Z"):
                return
            time.sleep(0.02)
        self.fail(message)

    def test_required_input_is_a_frozen_catalog_derived_result(self) -> None:
        payload = b"owned bytes"
        spec = self.spec(payload)
        required = self.installer.required_input(spec)
        self.assertIsInstance(required, AcquisitionRequired)
        self.assertEqual(required.asset_id, spec.asset_id)
        self.assertEqual(required.official_url, spec.official_url)
        self.assertEqual(required.reason, spec.reason)
        self.assertEqual(required.input_bytes, len(payload))
        self.assertEqual(required.input_sha256, spec.input_sha256)
        self.assertTrue(required.conversion_required)
        self.assertEqual(required.conversion_tool_asset_id, "game.extractor")
        with self.assertRaises(FrozenInstanceError):
            required.asset_id = "spoofed"  # type: ignore[misc]

        with self.assertRaisesRegex(InstallError, "canonical validation"):
            self.installer.required_input(
                replace(spec, official_url="not-an-official-url")
            )

        mirrored = json.loads(
            (ROOT / "tests/fixtures/contracts/valid/asset-mirrored.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIsNone(
            self.installer.required_input(AssetSpec.from_mapping(mirrored))
        )

    def test_input_mismatch_and_special_files_never_run_converter(self) -> None:
        payload = b"expected-input"
        marker = self.root / "converter-ran"
        script = f"""#!/bin/sh
set -eu
touch {marker}
exit 99
"""
        spec = self.spec(payload)
        tool = self.tool("game.extractor", script)
        catalog = self.catalog(spec, tool)
        authorized = self.input_file(payload, "authorized.bin")
        wrong_digest = self.input_file(b"wrong-digest!!", "wrong-digest.bin")
        wrong_size = self.input_file(b"short", "wrong-size.bin")
        directory = self.root / "directory-input"
        directory.mkdir()
        symlink = self.root / "symlink-input"
        symlink.symlink_to(authorized)
        fifo = self.root / "fifo-input"
        os.mkfifo(fifo, 0o600)

        with self.open_store() as store:
            self.authorize(store, spec, authorized)
            for path in (wrong_digest, wrong_size, directory, symlink, fifo, Path("/dev/null")):
                with self.subTest(path=path), self.assertRaises(BindingMismatch):
                    self.installer.ensure_user_supplied_asset(
                        spec, catalog, store, self.release, str(path)
                    )
        self.assertFalse(marker.exists())
        self.assert_no_selection_or_stage(spec)

    def test_conversion_uses_pinned_tool_minimal_env_eof_and_closed_fds(self) -> None:
        payload = b"licensed game data"
        argv_zero = self.root / "converter-argv-zero"
        sentinel = os.open(self.root / "sentinel", os.O_RDWR | os.O_CREAT, 0o600)
        high_descriptor = fcntl.fcntl(sentinel, fcntl.F_DUPFD_CLOEXEC, 200)
        os.close(sentinel)
        script = """#!/bin/sh
set -eu
test "$1" = extract
if IFS= read -r unexpected; then exit 41; fi
test -z "${PRIVATE_TOKEN+x}"
test ! -e "/proc/self/fd/$4"
printf '%s' "$0" > "$5"
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        spec = self.spec(
            payload,
            argv=(
                "extract",
                "{input}",
                "{output}",
                str(high_descriptor),
                str(argv_zero),
            ),
        )
        tool = self.tool("game.extractor", script)
        catalog = self.catalog(spec, tool)
        input_path = self.input_file(payload)
        reports: list[str] = []
        try:
            with self.open_store() as store:
                self.authorize(store, spec, input_path)
                selected = self.installer.ensure_user_supplied_asset(
                    spec,
                    catalog,
                    store,
                    self.release,
                    str(input_path),
                    reports.append,
                )
        finally:
            os.close(high_descriptor)
        self.assertEqual(len(selected), 1)
        self.assertEqual(Path(selected[0]).read_bytes(), payload)
        self.assertEqual(
            argv_zero.read_text(encoding="utf-8"),
            str(Path(self.installer.destination(tool)) / tool.binary),
        )
        self.assertNotIn(str(input_path), "\n".join(reports))

    def test_missing_receipt_refuses_before_tool_install_or_conversion(self) -> None:
        payload = b"unauthorized input"
        marker = self.root / "unauthorized-converter-ran"
        spec = self.spec(payload)
        tool = self.tool(
            "game.extractor",
            f"#!/bin/sh\ntouch {marker}\nexit 99\n",
        )
        input_path = self.input_file(payload)
        with self.open_store() as store, self.assertRaises(ReceiptMissing):
            self.installer.ensure_user_supplied_asset(
                spec,
                self.catalog(spec, tool),
                store,
                self.release,
                str(input_path),
            )
        self.assertFalse(marker.exists())
        self.assertFalse(Path(self.installer.destination(tool)).exists())
        self.assert_no_selection_or_stage(spec)

    def test_identity_path_is_explicit_single_file_and_never_extracts(self) -> None:
        payload = b"identity bytes"
        input_path = self.input_file(payload)
        spec = self.spec(payload, conversion=False)
        catalog = self.catalog(spec)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            selected = self.installer.ensure_user_supplied_asset(
                spec, catalog, store, self.release, str(input_path)
            )
        self.assertEqual(Path(selected[0]).read_bytes(), payload)

        multi = replace(
            self.spec(
                payload,
                asset_id="game.identity-multi",
                version="multi",
                conversion=False,
            ),
            files=(
                AssetFileSpec("one.bin", len(payload), hashlib.sha256(payload).hexdigest()),
                AssetFileSpec("two.bin", len(payload), hashlib.sha256(payload).hexdigest()),
            ),
            installed_bytes=len(payload) * 2,
        )
        mismatch_base = self.spec(
            payload,
            asset_id="game.identity-mismatch",
            version="mismatch",
            conversion=False,
        )
        mismatch = replace(
            mismatch_base,
            files=(replace(mismatch_base.files[0], sha256="f" * 64),),
        )
        with self.open_store("identity-refusals") as store:
            for rejected, message in (
                (multi, "exactly one"),
                (mismatch, "must equal"),
            ):
                with self.subTest(asset=rejected.asset_id):
                    self.authorize(store, rejected, input_path)
                    with self.assertRaisesRegex(InstallError, message):
                        self.installer.ensure_user_supplied_asset(
                            rejected,
                            self.catalog(rejected),
                            store,
                            self.release,
                            str(input_path),
                        )
                    self.assert_no_selection_or_stage(rejected)

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("expanded.txt", b"must stay archived")
        archive_payload = archive_buffer.getvalue()
        archive_input = self.input_file(archive_payload, "identity.zip")
        archive_spec = self.spec(
            archive_payload,
            asset_id="game.identity-archive",
            version="archive",
            output_path="archive.zip",
            conversion=False,
        )
        with self.open_store("identity-archive-receipts") as store:
            self.authorize(store, archive_spec, archive_input)
            selected = self.installer.ensure_user_supplied_asset(
                archive_spec,
                self.catalog(archive_spec),
                store,
                self.release,
                str(archive_input),
            )
        self.assertEqual(Path(selected[0]).read_bytes(), archive_payload)
        self.assertFalse(Path(selected[0]).with_name("expanded.txt").exists())

    def test_missing_partial_extra_and_executable_outputs_never_select(self) -> None:
        payload = b"expected output"
        input_path = self.input_file(payload)
        scripts = {
            "missing": "#!/bin/sh\nexit 0\n",
            "partial": """#!/bin/sh
mkdir -p "$3/game"
printf wrong > "$3/game/data.pak"
""",
            "extra": """#!/bin/sh
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
touch "$3/extra"
""",
            "executable": """#!/bin/sh
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
chmod 700 "$3/game/data.pak"
""",
            "hardlink": """#!/bin/sh
mkdir -p "$3/game"
ln "$2" "$3/game/data.pak"
""",
        }
        with self.open_store() as store:
            for index, (name, script) in enumerate(scripts.items()):
                spec = self.spec(
                    payload,
                    asset_id=f"game.bad-output-{name}",
                    version=str(index),
                    tool_id=f"tool.{name}",
                )
                tool = self.tool(f"tool.{name}", script)
                self.authorize(store, spec, input_path)
                with self.subTest(case=name), self.assertRaisesRegex(
                    InstallError, "does not match"
                ):
                    self.installer.ensure_user_supplied_asset(
                        spec,
                        self.catalog(spec, tool),
                        store,
                        self.release,
                        str(input_path),
                    )
                self.assert_no_selection_or_stage(spec)

    def test_converter_timeout_kills_ignoring_process_group(self) -> None:
        payload = b"timeout input"
        pid_path = self.root / "grandchild.pid"
        script = """#!/bin/sh
trap '' TERM
(trap '' TERM; while :; do sleep 1; done) &
echo $! > "$4"
while :; do sleep 1; done
"""
        spec = self.spec(
            payload,
            argv=("hang", "{input}", "{output}", str(pid_path)),
        )
        tool = self.tool("game.extractor", script)
        input_path = self.input_file(payload)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with (
                mock.patch("kilix_content.install._CONVERTER_TIMEOUT_SECONDS", 0.2),
                mock.patch(
                    "kilix_content.install._CONVERTER_TERMINATE_GRACE_SECONDS", 0.1
                ),
                self.assertRaisesRegex(InstallError, "timed out"),
            ):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assertTrue(pid_path.exists())
        pid = int(pid_path.read_text(encoding="ascii"))
        self.assert_process_stopped(
            pid, "converter grandchild survived process-group timeout"
        )
        self.assert_no_selection_or_stage(spec)

    def test_terminal_parent_kills_closed_stdio_descendants(self) -> None:
        payload = b"terminal parent input"
        input_path = self.input_file(payload)
        for returncode in (0, 7):
            with self.subTest(returncode=returncode):
                tool_id = f"tool.closed-stdio-{returncode}"
                asset_id = f"game.closed-stdio-{returncode}"
                pid_path = self.root / f"closed-stdio-{returncode}.pid"
                script = f"""#!/bin/sh
set -eu
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
(trap '' TERM; exec </dev/null >/dev/null 2>&1; exec sleep 60) &
echo $! > "$4"
exit {returncode}
"""
                spec = self.spec(
                    payload,
                    asset_id=asset_id,
                    version="terminal-parent",
                    tool_id=tool_id,
                    argv=("convert", "{input}", "{output}", str(pid_path)),
                )
                tool = self.tool(tool_id, script)
                with self.open_store(f"closed-stdio-{returncode}-receipts") as store:
                    self.authorize(store, spec, input_path)
                    with mock.patch(
                        "kilix_content.install._CONVERTER_TERMINATE_GRACE_SECONDS",
                        0.05,
                    ):
                        if returncode:
                            with self.assertRaisesRegex(
                                InstallError, f"status {returncode}"
                            ):
                                self.installer.ensure_user_supplied_asset(
                                    spec,
                                    self.catalog(spec, tool),
                                    store,
                                    self.release,
                                    str(input_path),
                                )
                        else:
                            selected = self.installer.ensure_user_supplied_asset(
                                spec,
                                self.catalog(spec, tool),
                                store,
                                self.release,
                                str(input_path),
                            )
                            self.assertEqual(Path(selected[0]).read_bytes(), payload)
                self.assertTrue(pid_path.exists())
                self.assert_process_stopped(
                    int(pid_path.read_text(encoding="ascii")),
                    f"closed-stdio descendant survived parent status {returncode}",
                )
                if returncode:
                    self.assert_no_selection_or_stage(spec)
                else:
                    parent = Path(self.installer.asset_destination(spec)).parent
                    self.assertFalse(
                        any(
                            path.name.startswith(".asset-install-")
                            for path in parent.iterdir()
                        )
                    )

    def test_converter_diagnostics_are_tail_bounded_and_terminal_safe(self) -> None:
        payload = b"diagnostic input"
        diagnostic_bytes = int(
            os.environ.get("KILIX_TEST_CONVERTER_OUTPUT_BYTES", str(8 * 1024 * 1024))
        )
        script = f"""#!/usr/bin/python3
import sys
block = b'A' * (1024 * 1024)
remaining = {diagnostic_bytes}
while remaining:
    part = block[:min(remaining, len(block))]
    sys.stdout.buffer.write(part)
    remaining -= len(part)
sys.stdout.buffer.write('TAIL %s {{}} \\x1b[31m private \\u202e token'.encode())
raise SystemExit(7)
"""
        spec = self.spec(payload)
        tool = self.tool("game.extractor", script)
        input_path = self.input_file(payload)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with self.assertRaises(InstallError) as raised:
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )
        message = str(raised.exception)
        self.assertLessEqual(len(message), 2200)
        self.assertIn("TAIL %s {}", message)
        self.assertIn("private", message)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\u202e", message)
        self.assertNotIn(str(input_path), message)
        self.assert_no_selection_or_stage(spec)

    def test_concurrent_callers_share_one_conversion(self) -> None:
        payload = b"concurrent input"
        counter = self.root / "conversion-count"
        script = """#!/bin/sh
set -eu
printf x >> "$4"
sleep 0.2
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        spec = self.spec(
            payload,
            argv=("convert", "{input}", "{output}", str(counter)),
        )
        tool = self.tool("game.extractor", script)
        catalog = self.catalog(spec, tool)
        input_path = self.input_file(payload)
        results: list[tuple[str, ...]] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(3)

        with self.open_store() as store:
            self.authorize(store, spec, input_path)

            def worker() -> None:
                barrier.wait()
                try:
                    results.append(
                        self.installer.ensure_user_supplied_asset(
                            spec,
                            catalog,
                            store,
                            self.release,
                            str(input_path),
                        )
                    )
                except BaseException as exc:  # noqa: BLE001 - test capture
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(counter.read_bytes(), b"x")

    def test_receipt_removed_during_conversion_blocks_selection(self) -> None:
        payload = b"revocation input"
        started = self.root / "converter-started"
        proceed = self.root / "converter-proceed"
        script = """#!/bin/sh
set -eu
touch "$4"
while test ! -e "$5"; do sleep 0.02; done
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        spec = self.spec(
            payload,
            argv=(
                "convert",
                "{input}",
                "{output}",
                str(started),
                str(proceed),
            ),
        )
        tool = self.tool("game.extractor", script)
        input_path = self.input_file(payload)
        errors: list[BaseException] = []
        with self.open_store() as store:
            self.authorize(store, spec, input_path)

            def worker() -> None:
                try:
                    self.installer.ensure_user_supplied_asset(
                        spec,
                        self.catalog(spec, tool),
                        store,
                        self.release,
                        str(input_path),
                    )
                except BaseException as exc:  # noqa: BLE001 - test capture
                    errors.append(exc)

            thread = threading.Thread(target=worker)
            thread.start()
            deadline = time.monotonic() + 3
            while not started.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(started.exists())
            lock_probe_started = time.monotonic()
            self.assertEqual(len(store.list_metadata()), 1)
            self.assertLess(time.monotonic() - lock_probe_started, 1.0)
            for receipt in Path(store.root).glob("*.json"):
                receipt.unlink()
            proceed.touch()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ReceiptMissing)
        self.assert_no_selection_or_stage(spec)

    def test_path_replacement_uses_pinned_bytes_but_open_file_mutation_fails(self) -> None:
        payload = b"original-pinned"
        replacement = b"replaced-path!!"
        self.assertEqual(len(payload), len(replacement))
        started = self.root / "path-started"
        proceed = self.root / "path-proceed"
        script = """#!/bin/sh
set -eu
touch "$4"
while test ! -e "$5"; do sleep 0.02; done
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        spec = self.spec(
            payload,
            argv=(
                "convert",
                "{input}",
                "{output}",
                str(started),
                str(proceed),
            ),
        )
        tool = self.tool("game.extractor", script)
        input_path = self.input_file(payload)
        results: list[tuple[str, ...]] = []
        errors: list[BaseException] = []
        with self.open_store() as store:
            self.authorize(store, spec, input_path)

            def worker() -> None:
                try:
                    results.append(
                        self.installer.ensure_user_supplied_asset(
                            spec,
                            self.catalog(spec, tool),
                            store,
                            self.release,
                            str(input_path),
                        )
                    )
                except BaseException as exc:  # noqa: BLE001 - test capture
                    errors.append(exc)

            thread = threading.Thread(target=worker)
            thread.start()
            deadline = time.monotonic() + 3
            while not started.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(started.exists())
            input_path.rename(self.root / "opened-original.bin")
            input_path.write_bytes(replacement)
            proceed.touch()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(Path(results[0][0]).read_bytes(), payload)

        second_root = self.root / "mutation-case"
        second_installer = Installer(str(second_root / "content"))
        second_input = second_root / "input.bin"
        second_input.parent.mkdir(parents=True, exist_ok=True)
        second_input.write_bytes(payload)
        second_spec = self.spec(
            payload,
            asset_id="game.mutated-open-file",
            version="mutation",
            tool_id="tool.mutation",
            argv=(
                "convert",
                "{input}",
                "{output}",
                str(second_root / "started"),
                str(second_root / "proceed"),
            ),
        )
        self.installer = second_installer
        second_tool = self.tool("tool.mutation", script)
        errors = []
        with open_test_store(str(second_root / "receipts")) as store:
            self.authorize(store, second_spec, second_input)

            def mutation_worker() -> None:
                try:
                    second_installer.ensure_user_supplied_asset(
                        second_spec,
                        self.catalog(second_spec, second_tool),
                        store,
                        self.release,
                        str(second_input),
                    )
                except BaseException as exc:  # noqa: BLE001 - test capture
                    errors.append(exc)

            thread = threading.Thread(target=mutation_worker)
            thread.start()
            started_path = second_root / "started"
            deadline = time.monotonic() + 3
            while not started_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(started_path.exists())
            second_input.write_bytes(replacement)
            (second_root / "proceed").touch()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], BindingMismatch)
        self.assertFalse(
            Path(second_installer.asset_destination(second_spec)).exists()
        )

    def test_tool_resolution_failures_do_not_fall_back_to_assets_or_path(self) -> None:
        payload = b"tool boundary"
        input_path = self.input_file(payload)
        spec = self.spec(payload)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with self.assertRaisesRegex(InstallError, "absent"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec),
                    store,
                    self.release,
                    str(input_path),
                )

            no_binary = ContentSpec(
                content_id="game.extractor",
                label="No binary",
                kind="tool",
                icon="",
                description="",
                source_type="custom",
            )
            with self.assertRaisesRegex(InstallError, "no executable"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, no_binary),
                    store,
                    self.release,
                    str(input_path),
                )

            unpinned = ContentSpec(
                content_id="game.extractor",
                label="Unpinned converter",
                kind="tool",
                icon="",
                description="",
                source_type="custom",
                binary="converter",
            )
            unpinned_executable = Path(self.installer.destination(unpinned)) / "converter"
            unpinned_executable.parent.mkdir(parents=True, exist_ok=True)
            unpinned_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            unpinned_executable.chmod(0o700)
            with self.assertRaisesRegex(InstallError, "pinned Git or archive"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, unpinned),
                    store,
                    self.release,
                    str(input_path),
                )

        self_ref = self.spec(
            payload,
            asset_id="game.self-tool",
            version="self",
            tool_id="game.self-tool",
        )
        self_tool = self.tool("game.self-tool", "#!/bin/sh\nexit 1\n")
        with self.open_store("self-tool-receipts") as store:
            self.authorize(store, self_ref, input_path)
            with self.assertRaisesRegex(InstallError, "self-referential"):
                self.installer.ensure_user_supplied_asset(
                    self_ref,
                    self.catalog(self_ref, self_tool),
                    store,
                    self.release,
                    str(input_path),
                )

        escaping = ContentSpec(
            content_id="game.extractor",
            label="Escaping tool",
            kind="tool",
            icon="",
            description="",
            source_type="custom",
            binary="../outside",
        )
        escaping_spec = self.spec(
            payload,
            asset_id="game.escaping-tool",
            version="escape",
        )
        with self.open_store("escaping-tool-receipts") as store:
            self.authorize(store, escaping_spec, input_path)
            with self.assertRaises(InstallError):
                self.installer.ensure_user_supplied_asset(
                    escaping_spec,
                    self.catalog(escaping_spec, escaping),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assert_no_selection_or_stage(escaping_spec)

    def test_direct_content_specs_cannot_remove_or_malformed_source_pins(self) -> None:
        payload = b"canonical tool pin boundary"
        input_path = self.input_file(payload)
        archive_digests = {
            "empty": "",
            "short": "0" * 63,
            "uppercase": "A" * 64,
            "nonhex": "g" * 64,
        }
        script = """#!/bin/sh
set -eu
touch "$4"
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        for index, (case, digest) in enumerate(archive_digests.items()):
            with self.subTest(source="archive", case=case):
                tool_id = f"tool.archive-pin-{case}"
                marker = self.root / f"archive-pin-{case}.ran"
                pinned = self.archive_tool(tool_id, script)
                if index == 0:
                    # Prove validation precedes readiness even when the exact
                    # pinned installation already exists.
                    self.installer.ensure(pinned)
                malformed = replace(pinned, sha256=digest)
                spec = self.spec(
                    payload,
                    asset_id=f"game.archive-pin-{case}",
                    version="malformed",
                    tool_id=tool_id,
                    argv=("convert", "{input}", "{output}", str(marker)),
                )
                with self.open_store(f"archive-pin-{case}-receipts") as store:
                    self.authorize(store, spec, input_path)
                    with (
                        mock.patch("kilix_content.install.download") as acquisition,
                        self.assertRaisesRegex(InstallError, "canonical validation"),
                    ):
                        self.installer.ensure_user_supplied_asset(
                            spec,
                            self.catalog(spec, malformed),
                            store,
                            self.release,
                            str(input_path),
                        )
                    acquisition.assert_not_called()
                self.assertFalse(marker.exists())
                self.assert_no_selection_or_stage(spec)
                self.assertFalse(
                    any(
                        path.name.startswith(".converter-attestation-")
                        for path in Path(self.installer.destination(malformed)).glob("*")
                    )
                )

        git_refs = {
            "missing": "",
            "mutable": "main",
            "short": "0" * 39,
            "uppercase": "A" * 40,
            "nonhex": "g" * 40,
        }
        for case, ref in git_refs.items():
            with self.subTest(source="git", case=case):
                tool_id = f"tool.git-pin-{case}"
                marker = self.root / f"git-pin-{case}.ran"
                pinned = self.tool(tool_id, script)
                malformed = replace(pinned, ref=ref)
                spec = self.spec(
                    payload,
                    asset_id=f"game.git-pin-{case}",
                    version="malformed",
                    tool_id=tool_id,
                    argv=("convert", "{input}", "{output}", str(marker)),
                )
                with self.open_store(f"git-pin-{case}-receipts") as store:
                    self.authorize(store, spec, input_path)
                    with (
                        mock.patch("kilix_content.install._run") as acquisition,
                        self.assertRaisesRegex(InstallError, "canonical validation"),
                    ):
                        self.installer.ensure_user_supplied_asset(
                            spec,
                            self.catalog(spec, malformed),
                            store,
                            self.release,
                            str(input_path),
                        )
                    acquisition.assert_not_called()
                self.assertFalse(marker.exists())
                self.assertFalse(
                    Path(self.installer.destination(malformed)).exists()
                )
                self.assert_no_selection_or_stage(spec)

        defense = self.archive_tool("tool.archive-defense", script)
        defense = replace(defense, sha256="")
        with (
            mock.patch("kilix_content.install.download") as acquisition,
            self.assertRaisesRegex(InstallError, "archive source identity"),
        ):
            self.installer._ensure_archive(defense, lambda _message: None)
        acquisition.assert_not_called()

        class SpoofedContentSpec(ContentSpec):
            def canonicalized(self) -> ContentSpec:
                return self

        spoofed = SpoofedContentSpec(**{**defense.__dict__, "sha256": ""})
        with (
            mock.patch("kilix_content.install.download") as acquisition,
            self.assertRaisesRegex(InstallError, "canonical validation"),
        ):
            self.installer.ensure(spoofed)
        acquisition.assert_not_called()

    def test_replaced_pinned_git_tool_is_detected_before_use(self) -> None:
        payload = b"tool replacement input"
        marker = self.root / "replacement-converter-ran"
        spec = self.spec(payload)
        tool = self.tool(
            "game.extractor",
            """#!/bin/sh
set -eu
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
""",
        )
        installed = Path(self.installer.ensure(tool))
        installed.write_text(
            f"#!/bin/sh\ntouch {marker}\nexit 0\n",
            encoding="utf-8",
        )
        installed.chmod(0o700)
        input_path = self.input_file(payload)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with self.assertRaisesRegex(InstallError, "modified managed checkout"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assertFalse(marker.exists())
        self.assert_no_selection_or_stage(spec)

    def test_attestation_detects_replaced_build_and_archive_tools(self) -> None:
        payload = b"attested converter input"
        input_path = self.input_file(payload)
        script = """#!/bin/sh
set -eu
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""
        tools = (
            self.built_tool("tool.built-attestation", script),
            self.archive_tool("tool.archive-attestation", script),
        )
        with self.open_store() as store:
            for index, tool in enumerate(tools):
                asset_id = f"game.attestation-{index}"
                installed_spec = self.spec(
                    payload,
                    asset_id=asset_id,
                    version="installed",
                    tool_id=tool.content_id,
                )
                self.authorize(store, installed_spec, input_path)
                installed_paths = self.installer.ensure_user_supplied_asset(
                    installed_spec,
                    self.catalog(installed_spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )

                marker = self.root / f"replacement-ran-{index}"
                program = Path(self.installer.destination(tool)) / tool.binary
                program.write_text(
                    f"#!/bin/sh\ntouch {marker}\nexit 0\n",
                    encoding="utf-8",
                )
                program.chmod(0o700)
                replacement_spec = self.spec(
                    payload,
                    asset_id=asset_id,
                    version="replacement",
                    tool_id=tool.content_id,
                )
                self.authorize(store, replacement_spec, input_path)
                with self.subTest(source=tool.source_type), self.assertRaisesRegex(
                    InstallError, "attestation"
                ):
                    self.installer.ensure_user_supplied_asset(
                        replacement_spec,
                        self.catalog(replacement_spec, tool),
                        store,
                        self.release,
                        str(input_path),
                    )
                self.assertFalse(marker.exists())
                self.assert_no_selection_or_stage(replacement_spec)
                self.assertEqual(Path(installed_paths[0]).read_bytes(), payload)

    def test_abrupt_stage_failures_preserve_prior_version(self) -> None:
        payload = b"preserved prior bytes"
        input_path = self.input_file(payload)
        asset_id = "game.stage-abort"
        prior = self.spec(
            payload,
            asset_id=asset_id,
            version="prior",
            conversion=False,
        )
        tool = self.tool(
            "tool.stage-abort",
            """#!/bin/sh
set -eu
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
""",
        )
        with self.open_store() as store:
            self.authorize(store, prior, input_path)
            prior_paths = self.installer.ensure_user_supplied_asset(
                prior,
                self.catalog(prior),
                store,
                self.release,
                str(input_path),
            )
            original_verify = self.installer._verify_asset_directory

            for phase in ("copy", "convert", "verify", "exchange"):
                candidate = self.spec(
                    payload,
                    asset_id=asset_id,
                    version=phase,
                    tool_id=tool.content_id,
                )
                self.authorize(store, candidate, input_path)

                def abort_stage(candidate_spec: AssetSpec, selected: str) -> tuple[str, ...] | None:
                    if ".asset-install-" in selected:
                        raise KeyboardInterrupt
                    return original_verify(candidate_spec, selected)

                if phase == "copy":
                    patcher = mock.patch.object(
                        self.installer,
                        "_copy_verified_input",
                        side_effect=KeyboardInterrupt,
                    )
                elif phase == "convert":
                    patcher = mock.patch(
                        "kilix_content.install._run_converter",
                        side_effect=KeyboardInterrupt,
                    )
                elif phase == "verify":
                    patcher = mock.patch.object(
                        self.installer,
                        "_verify_asset_directory",
                        side_effect=abort_stage,
                    )
                else:
                    patcher = mock.patch.object(
                        self.installer,
                        "_replace_stage",
                        side_effect=KeyboardInterrupt,
                    )
                with (
                    self.subTest(phase=phase),
                    patcher,
                    self.assertRaises(KeyboardInterrupt),
                ):
                    self.installer.ensure_user_supplied_asset(
                        candidate,
                        self.catalog(candidate, tool),
                        store,
                        self.release,
                        str(input_path),
                    )
                self.assert_no_selection_or_stage(candidate)

        self.assertEqual(Path(prior_paths[0]).read_bytes(), payload)

    def test_copy_enospc_and_converter_failure_preserve_no_selection(self) -> None:
        payload = b"storage failure input"
        input_path = self.input_file(payload)
        spec = self.spec(payload)
        tool = self.tool("game.extractor", "#!/bin/sh\nexit 1\n")
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with (
                mock.patch(
                    "kilix_content.install.os.write",
                    side_effect=OSError(errno.ENOSPC, "no space"),
                ),
                self.assertRaisesRegex(InstallError, "stage"),
            ):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )
            with self.assertRaisesRegex(InstallError, "status 1"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec, tool),
                    store,
                    self.release,
                    str(input_path),
                )
            output_spec = self.spec(
                payload,
                asset_id="game.output-enospc",
                version="output-enospc",
                tool_id="tool.output-enospc",
            )
            output_tool = self.tool(
                "tool.output-enospc",
                """#!/bin/sh
set -eu
mkdir -p "$3/game"
dd if="$2" of=/dev/full status=none
""",
            )
            self.authorize(store, output_spec, input_path)
            with self.assertRaisesRegex(InstallError, "status"):
                self.installer.ensure_user_supplied_asset(
                    output_spec,
                    self.catalog(output_spec, output_tool),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assert_no_selection_or_stage(spec)
        self.assert_no_selection_or_stage(output_spec)

    def test_asset_parent_and_lock_metadata_fail_closed(self) -> None:
        payload = b"lock metadata"
        input_path = self.input_file(payload)
        spec = self.spec(payload, conversion=False)
        destination = Path(self.installer.asset_destination(spec))
        unsafe_target = self.root / "unsafe-target"
        unsafe_target.mkdir()
        destination.parent.symlink_to(unsafe_target, target_is_directory=True)
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            with self.assertRaisesRegex(InstallError, "asset root"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assertFalse((unsafe_target / spec.version).exists())

        destination.parent.unlink()
        destination.parent.mkdir(mode=0o700)
        identity = hashlib.sha256(
            f"{spec.asset_id}\x00{spec.version}".encode("utf-8")
        ).hexdigest()
        victim = self.root / "lock-victim"
        victim.write_bytes(b"unchanged")
        victim.chmod(0o600)
        os.link(victim, destination.parent / f".install-{identity}.lock")
        with self.open_store("hardlink-lock-receipts") as store:
            self.authorize(store, spec, input_path)
            with self.assertRaisesRegex(InstallError, "lock"):
                self.installer.ensure_user_supplied_asset(
                    spec,
                    self.catalog(spec),
                    store,
                    self.release,
                    str(input_path),
                )
        self.assertEqual(victim.read_bytes(), b"unchanged")
        self.assertEqual(victim.stat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
