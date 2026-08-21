"""Regressions for the seams where the 0.2.0 baseline and the F100 line meet.

Each side is independently covered by its own suite. These tests prove the
combined behavior: the baseline's executable package-identity locking, bounded
child-command timeouts and process-group cleanup apply to the F100 asset
conversion-tool path, and the merged packaged catalog still carries the whole
published 0.2.0 projection alongside the empty production asset array.
"""

from __future__ import annotations

import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from kilix_content import Catalog, ContentSpec, InstallError, Installer
from kilix_content import default_catalog
from kilix_content import install as install_module

# The F100 suite is reached through its module, never bound as a name here:
# a module-level alias would make unittest collect a second copy of it.
from tests import test_user_supplied

CONVERTER = """#!/bin/sh
set -eu
mkdir -p "$3/game"
cp "$2" "$3/game/data.pak"
"""


def _rebuilt(tool: ContentSpec, build: tuple[str, ...]) -> ContentSpec:
    """Copy a pinned tool specification with a different build command."""
    return ContentSpec(
        content_id=tool.content_id,
        label=tool.label,
        kind=tool.kind,
        icon=tool.icon,
        description=tool.description,
        source_type=tool.source_type,
        repository=tool.repository,
        ref=tool.ref,
        binary=tool.binary,
        build=build,
    )


class ConversionToolLockingTests(test_user_supplied.UserSuppliedAssetTests):
    """The F100 conversion tool installs under the baseline install lock."""

    def record_lock_acquisitions(self) -> list[str]:
        """Patch the baseline lock primitive to record every path it takes."""
        taken: list[str] = []
        original = install_module._acquire_install_lock

        def recording(lock_path: str) -> int:
            taken.append(lock_path)
            return original(lock_path)

        patcher = mock.patch.object(
            install_module, "_acquire_install_lock", recording
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return taken

    def test_conversion_tool_install_uses_the_baseline_package_lock(self) -> None:
        payload = b"baseline integration payload"
        spec = self.spec(payload)
        tool = self.built_tool("game.extractor", CONVERTER)
        catalog = self.catalog(spec, tool)
        input_path = self.input_file(payload)
        taken = self.record_lock_acquisitions()

        started = time.monotonic()
        with self.open_store() as store:
            self.authorize(store, spec, input_path)
            selected = self.installer.ensure_user_supplied_asset(
                spec, catalog, store, self.release, str(input_path)
            )
        elapsed = time.monotonic() - started

        # F100 behavior: the asset converted through the pinned tool and was
        # selected.
        self.assertTrue(selected)
        installed = Path(self.installer.asset_destination(spec)) / "game/data.pak"
        self.assertTrue(installed.is_file())
        self.assertEqual(installed.read_bytes(), payload)

        # Baseline behavior: installing that conversion tool went through the
        # cross-process package-identity lock keyed by its install identity.
        expected_lock = f".{tool.install_id}.lock"
        self.assertTrue(
            any(Path(path).name == expected_lock for path in taken),
            f"conversion tool did not take the baseline install lock; took {taken}",
        )
        # The nested asset-lock / tool-lock ordering does not deadlock.
        self.assertLess(elapsed, 60.0)

    def test_conversion_tool_build_is_bounded_by_the_baseline_timeout(self) -> None:
        """The merged tool path inherits the baseline child-command timeout."""
        self.assertEqual(
            Installer(str(self.root / "default")).command_timeout, 3600.0
        )
        bounded = Installer(
            str(self.root / "stalled"),
            env={"PRIVATE_TOKEN": "do-not-inherit"},
            command_timeout=2.0,
        )
        tool = self.built_tool("game.stalled", CONVERTER)
        stalling = _rebuilt(tool, ("sh", "-c", "sleep 60"))

        started = time.monotonic()
        with self.assertRaises(InstallError) as raised:
            bounded.ensure(stalling)
        elapsed = time.monotonic() - started

        # Baseline behavior: the stalled build is killed well inside its own
        # sleep, and the diagnostic stays bounded and free of inherited state.
        self.assertLess(elapsed, 30.0)
        detail = str(raised.exception)
        self.assertLessEqual(len(detail), 2000)
        self.assertNotIn("PRIVATE_TOKEN", detail)
        self.assertNotIn("do-not-inherit", detail)

    def test_independent_assets_build_their_shared_tool_once(self) -> None:
        """Two assets needing one tool perform exactly one build.

        The two assets hold different asset locks, so only the retained
        baseline package-identity lock can serialize the shared tool build.
        """
        counter = self.root / "build-count"
        first_payload = b"first shared-tool payload"
        second_payload = b"second shared-tool payload"
        first = self.spec(first_payload, asset_id="game.user-data")
        second = self.spec(second_payload, asset_id="game.other-data")
        tool = self.built_tool("game.extractor", CONVERTER)
        counting = _rebuilt(
            tool,
            (
                "sh",
                "-c",
                f'printf x >> "{counter}"; sleep 0.2; '
                "mkdir -p build; cp converter-source build/converter; "
                "chmod 700 build/converter",
            ),
        )
        catalog = Catalog(
            (counting,), schema_version=4, assets=(first, second)
        )
        inputs = {
            first.asset_id: self.input_file(first_payload, "first-input.bin"),
            second.asset_id: self.input_file(second_payload, "second-input.bin"),
        }
        errors: list[BaseException] = []
        barrier = threading.Barrier(3)

        with self.open_store() as store:
            for spec in (first, second):
                self.authorize(store, spec, inputs[spec.asset_id])

            def worker(spec) -> None:
                barrier.wait()
                try:
                    self.installer.ensure_user_supplied_asset(
                        spec,
                        catalog,
                        store,
                        self.release,
                        str(inputs[spec.asset_id]),
                    )
                except BaseException as exc:  # noqa: BLE001 - test capture
                    errors.append(exc)

            threads = [
                threading.Thread(target=worker, args=(spec,))
                for spec in (first, second)
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=60)
            self.assertFalse(any(thread.is_alive() for thread in threads))

        self.assertEqual([str(error) for error in errors], [])
        # Both assets were converted by the one shared tool ...
        for spec, payload in ((first, first_payload), (second, second_payload)):
            installed = (
                Path(self.installer.asset_destination(spec)) / "game/data.pak"
            )
            self.assertEqual(installed.read_bytes(), payload)
        # ... which the retained baseline lock built exactly once.
        self.assertEqual(counter.read_bytes(), b"x")


# ``ConversionToolLockingTests`` subclasses the F100 suite purely to reuse its
# asset/tool/receipt fixtures. Detach the inherited cases so they run once, in
# their own module, rather than a second time under this name.
for _inherited in [
    name
    for name in dir(test_user_supplied.UserSuppliedAssetTests)
    if name.startswith("test_")
]:
    setattr(ConversionToolLockingTests, _inherited, None)
del _inherited


class MergedCatalogProjectionTests(unittest.TestCase):
    """The packaged catalog keeps the published 0.2.0 projection."""

    # Identities published in 0.2.0 that the merge is required to keep.
    BASELINE_ONLY_IDS = ("kilix-land", "kilix-tmux-manager")
    BASELINE_CONTENT_COUNT = 41
    BASELINE_PACKAGE_IDS = ("kilix-tui-utils",)

    def setUp(self) -> None:
        self.catalog = default_catalog()

    def test_schema_is_v4_with_an_explicit_empty_production_asset_array(self) -> None:
        self.assertEqual(self.catalog.schema_version, 4)
        self.assertEqual(tuple(self.catalog.assets), ())

    def test_every_published_baseline_record_survives(self) -> None:
        identifiers = [entry.content_id for entry in self.catalog]
        self.assertEqual(len(identifiers), self.BASELINE_CONTENT_COUNT)
        self.assertEqual(len(set(identifiers)), len(identifiers))
        for identifier in self.BASELINE_ONLY_IDS:
            self.assertIn(identifier, identifiers)
            self.assertTrue(self.catalog.require(identifier).label)
        package_ids = [package.package_id for package in self.catalog.packages]
        for identifier in self.BASELINE_PACKAGE_IDS:
            self.assertIn(identifier, package_ids)

    def test_content_and_asset_identities_cannot_collide(self) -> None:
        content_ids = {entry.content_id for entry in self.catalog}
        asset_ids = {asset.asset_id for asset in self.catalog.assets}
        self.assertEqual(content_ids & asset_ids, set())
        package_ids = {package.package_id for package in self.catalog.packages}
        self.assertEqual(package_ids & asset_ids, set())


if __name__ == "__main__":
    unittest.main()
