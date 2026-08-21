"""Pure catalog-v5 and installation-authority contracts.

All functions in this module operate on supplied immutable data.  They do not
fetch sources, inspect a host, execute a build, or authorize an installation.
"""

from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .u1_core import (
    HEX40_RE,
    authorization_record_digest,
    catalog_digest,
    install_authority_digest,
    install_record_digest,
    output_binding_digest,
    refuse,
    require_array,
    require_digest,
    require_id,
    require_keys,
    require_object,
    require_relative_path,
    require_s64,
    require_sorted_unique,
    require_text,
    source_identity_digest,
)


SOURCE_KINDS = ("archive", "git", "mirrored", "user-supplied")
DEPENDENCY_ROLES = ("build", "conversion", "runtime")
LICENSE_DECISIONS = ("affirmative", "informational", "restricted", "user-supplied")
MAX_GRAPH_NODES = 8_192
MAX_GRAPH_EDGES = 16_384
MAX_GRAPH_DEPTH = 64
MEDIA_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$")


def _https_url(value: Any) -> str:
    text = require_text(value, maximum=2_048)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.hostname != parsed.hostname.lower()
        or urlunsplit(parsed) != text
    ):
        refuse("source URL is outside the frozen HTTPS grammar")
    return text


def _https_urls(value: Any) -> list[str]:
    urls = require_array(value, minimum=1, maximum=16)
    for url in urls:
        _https_url(url)
    if urls != sorted(urls) or len(urls) != len(set(urls)):
        refuse("source URLs are not sorted unique data")
    return urls


def _digest_ref(value: Any, *, digest_field: str = "sha256") -> dict[str, Any]:
    item = require_object(value)
    require_keys(item, required=("id", digest_field))
    require_id(item["id"])
    require_digest(item[digest_field])
    return item


def validate_source(value: Any) -> dict[str, Any]:
    """Validate one closed source union and return its base dict."""
    source = require_object(value)
    kind = source.get("kind")
    if kind == "archive":
        require_keys(
            source,
            required=(
                "kind",
                "urls",
                "sha256",
                "source_bytes",
                "source_bytes_max",
                "archive_format",
            ),
        )
        _https_urls(source["urls"])
        require_digest(source["sha256"])
        if source["archive_format"] not in {"tar", "tar.gz", "tar.xz", "zip"}:
            refuse("archive format is outside the frozen enum")
        length = require_s64(source["source_bytes"], positive=True)
        maximum = require_s64(source["source_bytes_max"], positive=True)
        if length > maximum:
            refuse("source length exceeds its frozen maximum")
    elif kind == "mirrored":
        require_keys(
            source,
            required=("kind", "urls", "sha256", "source_bytes", "source_bytes_max"),
        )
        _https_urls(source["urls"])
        require_digest(source["sha256"])
        length = require_s64(source["source_bytes"], positive=True)
        maximum = require_s64(source["source_bytes_max"], positive=True)
        if length > maximum:
            refuse("source length exceeds its frozen maximum")
    elif kind == "git":
        require_keys(
            source,
            required=("kind", "repository", "commit", "source_bytes_max", "submodules"),
        )
        _https_url(source["repository"])
        require_text(source["commit"], HEX40_RE, maximum=40)
        require_s64(source["source_bytes_max"], positive=True)
        submodules = require_array(source["submodules"], maximum=256)
        paths: set[str] = set()
        for raw_submodule in submodules:
            submodule = require_object(raw_submodule)
            require_keys(submodule, required=("path", "repository", "commit"))
            path = require_relative_path(submodule["path"])
            if path in paths:
                refuse("Git submodule path is duplicated")
            paths.add(path)
            _https_url(submodule["repository"])
            require_text(submodule["commit"], HEX40_RE, maximum=40)
        require_sorted_unique(submodules)
    elif kind == "user-supplied":
        require_keys(
            source,
            required=(
                "kind",
                "input_format",
                "input_sha256",
                "source_bytes",
                "source_bytes_max",
            ),
        )
        require_text(source["input_format"], MEDIA_TYPE_RE, maximum=127)
        require_digest(source["input_sha256"])
        length = require_s64(source["source_bytes"], positive=True)
        maximum = require_s64(source["source_bytes_max"], positive=True)
        if length > maximum:
            refuse("source length exceeds its frozen maximum")
    else:
        refuse("source kind is outside the frozen enum")
    return source


def validate_install_record(value: Any) -> dict[str, Any]:
    """Validate the complete install-record/v5 semantic core."""
    install = require_object(value)
    require_keys(
        install,
        required=(
            "schema",
            "version",
            "source",
            "build_argv",
            "output_format_version",
            "source_bytes_max",
            "temporary_bytes_max",
            "process_memory_bytes_max",
            "installed_bytes_max",
            "temporary_files_max",
            "installed_files_max",
            "dependencies",
            "system_requirements",
            "toolchain",
            "sandbox",
            "licenses",
        ),
        optional=("output_manifest_sha256",),
    )
    if install["schema"] != "kilix.content.install-record/v5":
        refuse("install record schema is not v5")
    require_text(install["version"], maximum=128)
    source = validate_source(install["source"])
    source_maximum = require_s64(install["source_bytes_max"], positive=True)
    if source_maximum != source["source_bytes_max"]:
        refuse("install and source maximums diverge")
    argv = require_array(install["build_argv"], maximum=128)
    for argument in argv:
        require_text(argument, maximum=4_096, allow_empty=True)
    require_s64(install["output_format_version"], positive=True)
    for name in (
        "temporary_bytes_max",
        "process_memory_bytes_max",
        "installed_bytes_max",
        "temporary_files_max",
        "installed_files_max",
    ):
        require_s64(install[name], positive=True)
    if "output_manifest_sha256" in install:
        require_digest(install["output_manifest_sha256"])

    dependencies = require_array(install["dependencies"], maximum=4_096)
    dependency_ids: set[str] = set()
    for raw_dependency in dependencies:
        dependency = require_object(raw_dependency)
        require_keys(dependency, required=("id", "role"))
        identifier = require_id(dependency["id"])
        if identifier in dependency_ids:
            refuse("dependency identifier is duplicated")
        dependency_ids.add(identifier)
        if dependency["role"] not in DEPENDENCY_ROLES:
            refuse("dependency role is outside the frozen enum")
    require_sorted_unique(dependencies)
    declares_build = any(
        dependency["role"] in {"build", "conversion"} for dependency in dependencies
    )
    if declares_build != bool(argv):
        refuse("build argv and build or conversion declaration diverge")

    requirements = require_array(install["system_requirements"], maximum=256)
    requirement_ids: set[str] = set()
    for raw_requirement in requirements:
        requirement = _digest_ref(raw_requirement, digest_field="manifest_sha256")
        if requirement["id"] in requirement_ids:
            refuse("system requirement reference is duplicated")
        requirement_ids.add(requirement["id"])
    require_sorted_unique(requirements)
    _digest_ref(install["toolchain"])
    _digest_ref(install["sandbox"])

    licenses = require_array(install["licenses"], minimum=1, maximum=256)
    license_ids: set[str] = set()
    for raw_license in licenses:
        license_record = require_object(raw_license)
        require_keys(license_record, required=("id", "text_sha256", "decision"))
        identifier = require_id(license_record["id"])
        if identifier in license_ids:
            refuse("license identifier is duplicated")
        license_ids.add(identifier)
        require_digest(license_record["text_sha256"])
        if license_record["decision"] not in LICENSE_DECISIONS:
            refuse("license decision is outside the frozen enum")
    require_sorted_unique(licenses)
    return install


def _validate_profile_refs(value: Any, *, digest_field: str) -> dict[str, str]:
    entries = require_array(value, maximum=256)
    result: dict[str, str] = {}
    paths: set[str] = set()
    for raw_entry in entries:
        entry = require_object(raw_entry)
        require_keys(entry, required=("id", "resource_path", digest_field))
        identifier = require_id(entry["id"])
        path = require_relative_path(entry["resource_path"])
        if identifier in result or path in paths:
            refuse("profile resource identity is duplicated")
        result[identifier] = require_digest(entry[digest_field])
        paths.add(path)
    require_sorted_unique(entries)
    return result


def _entry_kind_map(catalog: Mapping[str, Any]) -> dict[str, str]:
    result = {entry["id"]: "package" for entry in catalog["packages"]}
    result.update({entry["id"]: "content" for entry in catalog["contents"]})
    result.update({entry["id"]: "asset" for entry in catalog["assets"]})
    result.update({entry["content_id"]: "alias" for entry in catalog["aliases"]})
    return result


def validate_catalog_v5(value: Any) -> None:
    catalog = require_object(value)
    require_keys(
        catalog,
        required=(
            "schema",
            "release_id",
            "packages",
            "contents",
            "assets",
            "aliases",
            "system_requirement_profiles",
            "toolchain_profiles",
            "sandbox_profiles",
            "license_manifest_id",
        ),
    )
    if catalog["schema"] != "kilix.content.catalog/v5":
        refuse("catalog schema is not v5")
    require_id(catalog["release_id"])
    require_id(catalog["license_manifest_id"])
    system_profiles = _validate_profile_refs(
        catalog["system_requirement_profiles"], digest_field="manifest_sha256"
    )
    toolchains = _validate_profile_refs(
        catalog["toolchain_profiles"], digest_field="profile_sha256"
    )
    sandboxes = _validate_profile_refs(
        catalog["sandbox_profiles"], digest_field="profile_sha256"
    )

    namespace: dict[str, str] = {}
    stable_slots: set[str] = set()
    installables: dict[str, Mapping[str, Any]] = {}
    declared_members: dict[str, tuple[str, str]] = {}

    packages = require_array(catalog["packages"], maximum=4_096)
    for raw_package in packages:
        package = require_object(raw_package)
        require_keys(package, required=("id", "stable_slot", "install", "members"))
        identifier = require_id(package["id"])
        slot = require_id(package["stable_slot"])
        if (
            identifier in namespace
            or identifier in declared_members
            or slot in stable_slots
        ):
            refuse("package identity or stable slot collides")
        namespace[identifier] = "package"
        stable_slots.add(slot)
        install = validate_install_record(package["install"])
        members = require_array(package["members"], minimum=1, maximum=4_096)
        member_paths: set[str] = set()
        for raw_member in members:
            member = require_object(raw_member)
            require_keys(member, required=("content_id", "member_path"))
            member_id = require_id(member["content_id"])
            member_path = require_relative_path(member["member_path"])
            if (
                member_id in namespace
                or member_id in declared_members
                or member_path in member_paths
            ):
                refuse("package member identity or path collides")
            declared_members[member_id] = (identifier, member_path)
            member_paths.add(member_path)
        require_sorted_unique(members)
        if "output_manifest_sha256" not in install:
            refuse("package lacks output manifest authority")
        installables[identifier] = package
    require_sorted_unique(packages)

    for collection, kind in (
        (catalog["contents"], "content"),
        (catalog["assets"], "asset"),
    ):
        entries = require_array(collection, maximum=4_096)
        for raw_entry in entries:
            entry = require_object(raw_entry)
            required = (
                ("id", "stable_slot", "install", "output_manifest_sha256")
                if kind == "asset"
                else (
                    "id",
                    "stable_slot",
                    "install",
                )
            )
            require_keys(entry, required=required)
            identifier = require_id(entry["id"])
            slot = require_id(entry["stable_slot"])
            if (
                identifier in namespace
                or identifier in declared_members
                or slot in stable_slots
            ):
                refuse("direct identity or stable slot collides")
            namespace[identifier] = kind
            stable_slots.add(slot)
            install = validate_install_record(entry["install"])
            if kind == "asset":
                digest = require_digest(entry["output_manifest_sha256"])
                if digest != install.get("output_manifest_sha256"):
                    refuse("direct asset and install output manifests diverge")
            elif "output_manifest_sha256" in install:
                refuse("direct content carries an asset output manifest")
            installables[identifier] = entry
        require_sorted_unique(entries)

    aliases = require_array(catalog["aliases"], maximum=4_096)
    observed_aliases: dict[str, tuple[str, str]] = {}
    for raw_alias in aliases:
        alias = require_object(raw_alias)
        require_keys(alias, required=("content_id", "package_id", "member_path"))
        content_id = require_id(alias["content_id"])
        package_id = require_id(alias["package_id"])
        member_path = require_relative_path(alias["member_path"])
        if content_id in namespace or content_id in observed_aliases:
            refuse("alias collides with the global namespace")
        if package_id not in installables or package_id not in {
            item["id"] for item in packages
        }:
            refuse("alias target is not a package")
        observed_aliases[content_id] = (package_id, member_path)
        namespace[content_id] = "alias"
    require_sorted_unique(aliases)
    if observed_aliases != declared_members:
        refuse("package members and aliases are not set-equal")

    if len(installables) > MAX_GRAPH_NODES:
        refuse("dependency graph exceeds the node bound")
    normalized = {identifier: identifier for identifier in installables}
    normalized.update(
        {identifier: target[0] for identifier, target in observed_aliases.items()}
    )
    graph: dict[str, list[str]] = {}
    edges = 0
    for identifier, installable in installables.items():
        targets: list[str] = []
        install = installable["install"]
        for dependency in install["dependencies"]:
            target = normalized.get(dependency["id"])
            if target is None:
                refuse("dependency is outside the global catalog namespace")
            targets.append(target)
        if len(targets) != len(set(targets)):
            refuse("dependencies collide after alias normalization")
        edges += len(targets)
        if edges > MAX_GRAPH_EDGES:
            refuse("dependency graph exceeds the edge bound")
        graph[identifier] = targets
        for reference in install["system_requirements"]:
            if system_profiles.get(reference["id"]) != reference["manifest_sha256"]:
                refuse("system requirement is not catalog authority")
        if toolchains.get(install["toolchain"]["id"]) != install["toolchain"]["sha256"]:
            refuse("toolchain is not catalog authority")
        if sandboxes.get(install["sandbox"]["id"]) != install["sandbox"]["sha256"]:
            refuse("sandbox is not catalog authority")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str, depth: int) -> None:
        if depth > MAX_GRAPH_DEPTH or identifier in visiting:
            refuse("dependency graph contains a cycle or exceeds its depth bound")
        if identifier in visited:
            return
        visiting.add(identifier)
        for child in graph[identifier]:
            visit(child, depth + 1)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in sorted(graph):
        visit(identifier, 0)


def _catalog_index(
    catalog: Mapping[str, Any],
) -> tuple[dict[str, tuple[str, Mapping[str, Any]]], dict[str, Mapping[str, Any]]]:
    installables: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for kind, collection in (
        ("package", catalog["packages"]),
        ("content", catalog["contents"]),
        ("asset", catalog["assets"]),
    ):
        installables.update({entry["id"]: (kind, entry) for entry in collection})
    aliases = {entry["content_id"]: entry for entry in catalog["aliases"]}
    return installables, aliases


def _derive_install_authority_binding(
    catalog_value: Any, request_id: str
) -> dict[str, Any]:
    """Test-only builder; caller mappings never establish packaged authority."""
    validate_catalog_v5(catalog_value)
    catalog = require_object(catalog_value)
    identifier = require_id(request_id)
    installables, aliases = _catalog_index(catalog)
    selected = installables.get(identifier)
    alias = aliases.get(identifier)
    if selected is None and alias is None:
        refuse("catalog request is not packaged")
    if alias is not None:
        selected = installables[alias["package_id"]]
    assert selected is not None
    kind, entry = selected
    if any(item["decision"] == "restricted" for item in entry["install"]["licenses"]):
        refuse("restricted installation cannot yield acquisition authority")
    members = entry["members"] if kind == "package" else []
    alias_members = (
        [item for item in catalog["aliases"] if item["package_id"] == entry["id"]]
        if kind == "package"
        else []
    )
    binding: dict[str, Any] = {
        "schema": "kilix.content.install-authority-binding/v1",
        "kind": kind,
        "stable_slot": entry["stable_slot"],
        "version": entry["install"]["version"],
        "release_id": catalog["release_id"],
        "catalog_sha256": catalog_digest(catalog),
        "install_record_sha256": install_record_digest(entry["install"]),
        "source_identity_sha256": source_identity_digest(entry["install"]["source"]),
        "content_ids": sorted(item["content_id"] for item in members),
        "alias_members": sorted(
            copy.deepcopy(alias_members), key=lambda item: item["content_id"]
        ),
    }
    output = entry.get(
        "output_manifest_sha256", entry["install"].get("output_manifest_sha256")
    )
    if output is not None:
        binding["output_manifest_sha256"] = output
    validate_authority_binding(binding)
    return binding


def validate_authority_binding(value: Any) -> None:
    binding = require_object(value)
    require_keys(
        binding,
        required=(
            "schema",
            "kind",
            "stable_slot",
            "version",
            "release_id",
            "catalog_sha256",
            "install_record_sha256",
            "source_identity_sha256",
            "content_ids",
            "alias_members",
        ),
        optional=("output_manifest_sha256",),
    )
    if binding["schema"] != "kilix.content.install-authority-binding/v1":
        refuse("install authority schema is not frozen")
    if binding["kind"] not in {"asset", "content", "package"}:
        refuse("install authority kind is outside the frozen enum")
    require_id(binding["stable_slot"])
    require_text(binding["version"], maximum=128)
    require_id(binding["release_id"])
    for name in ("catalog_sha256", "install_record_sha256", "source_identity_sha256"):
        require_digest(binding[name])
    content_ids = require_array(binding["content_ids"], maximum=4_096)
    for content_id in content_ids:
        require_id(content_id)
    if content_ids != sorted(content_ids) or len(content_ids) != len(set(content_ids)):
        refuse("authority content IDs are not sorted unique data")
    aliases = require_array(binding["alias_members"], maximum=4_096)
    for raw_alias in aliases:
        alias = require_object(raw_alias)
        require_keys(alias, required=("content_id", "package_id", "member_path"))
        require_id(alias["content_id"])
        require_id(alias["package_id"])
        require_relative_path(alias["member_path"])
    require_sorted_unique(aliases)
    if binding["kind"] == "package":
        if (
            not content_ids
            or [item["content_id"] for item in aliases] != content_ids
            or "output_manifest_sha256" not in binding
        ):
            refuse("package authority does not bind its complete alias projection")
    elif content_ids or aliases:
        refuse("direct authority contains package member authority")
    if binding["kind"] == "asset" and "output_manifest_sha256" not in binding:
        refuse("asset authority lacks output manifest authority")
    if binding["kind"] == "content" and "output_manifest_sha256" in binding:
        refuse("direct content authority carries an output manifest")
    if "output_manifest_sha256" in binding:
        require_digest(binding["output_manifest_sha256"])


def _validate_authority_against_catalog(
    value: Any, catalog: Any, request_id: str
) -> None:
    validate_authority_binding(value)
    if require_object(value) != _derive_install_authority_binding(catalog, request_id):
        refuse("install authority diverges from packaged catalog authority")


def validate_output_binding(value: Any) -> None:
    binding = require_object(value)
    require_keys(
        binding,
        required=(
            "schema",
            "install_authority_sha256",
            "source_sha256",
            "input_sha256",
            "dependency_sha256s",
            "toolchain_sha256",
            "sandbox_sha256",
            "selected_tree_sha256",
            "selected_bytes",
            "selected_files",
            "journal_schema",
            "output_format_version",
        ),
    )
    if binding["schema"] != "kilix.content.output-binding/v1":
        refuse("output binding schema is not frozen")
    for name in (
        "install_authority_sha256",
        "source_sha256",
        "input_sha256",
        "toolchain_sha256",
        "sandbox_sha256",
        "selected_tree_sha256",
    ):
        require_digest(binding[name])
    dependencies = require_array(binding["dependency_sha256s"], maximum=4_096)
    for digest in dependencies:
        require_digest(digest)
    if dependencies != sorted(dependencies) or len(dependencies) != len(
        set(dependencies)
    ):
        refuse("output dependency digests are not sorted unique data")
    require_s64(binding["selected_bytes"])
    require_s64(binding["selected_files"])
    require_id(binding["journal_schema"])
    require_s64(binding["output_format_version"], positive=True)


def _validate_output_against_authority(value: Any, authority: Any) -> None:
    from .u1_core import install_authority_digest

    validate_output_binding(value)
    validate_authority_binding(authority)
    if require_object(value)["install_authority_sha256"] != install_authority_digest(
        authority
    ):
        refuse("output binding does not bind the exact install authority")


def validate_authorization_v2(value: Any) -> None:
    record = require_object(value)
    require_keys(
        record,
        required=(
            "schema",
            "release_id",
            "catalog_sha256",
            "install_authority_sha256",
            "output_binding_sha256",
            "authorization_id",
            "record_sha256",
        ),
    )
    if record["schema"] != "kilix.install.authorization/v2":
        refuse("authorization schema is not v2")
    require_id(record["release_id"])
    require_id(record["authorization_id"])
    for name in (
        "catalog_sha256",
        "install_authority_sha256",
        "output_binding_sha256",
        "record_sha256",
    ):
        require_digest(record[name])
    if record["record_sha256"] != authorization_record_digest(record):
        refuse("authorization record digest is inconsistent")


def _validate_authorization_against_records(
    authorization_value: Any,
    catalog_value: Any,
    authority_value: Any,
    output_value: Any,
    request_id: str,
) -> None:
    """Recompute the complete catalog -> authority -> output -> authorization chain."""
    validate_authorization_v2(authorization_value)
    validate_catalog_v5(catalog_value)
    _validate_authority_against_catalog(authority_value, catalog_value, request_id)
    _validate_output_against_authority(output_value, authority_value)
    authorization = require_object(authorization_value)
    catalog = require_object(catalog_value)
    authority = require_object(authority_value)
    output = require_object(output_value)
    if (
        authorization["release_id"] != catalog["release_id"]
        or authorization["release_id"] != authority["release_id"]
        or authorization["catalog_sha256"] != catalog_digest(catalog)
        or authorization["install_authority_sha256"]
        != install_authority_digest(authority)
        or authorization["output_binding_sha256"] != output_binding_digest(output)
    ):
        refuse("authorization does not bind the exact admitted record chain")


def _validate_catalog_transition(previous: Any, current: Any) -> None:
    """Require an additive external review for every package/direct/alias kind change."""
    validate_catalog_v5(previous)
    validate_catalog_v5(current)
    old = _entry_kind_map(require_object(previous))
    new = _entry_kind_map(require_object(current))
    for identifier in set(old) & set(new):
        if old[identifier] != new[identifier]:
            refuse(
                "catalog kind transition requires separate packaged migration authority"
            )


def _validate_catalog_resource_bundle(
    catalog_value: Any,
    resources: Mapping[str, bytes],
    *,
    validate_json_resource: Callable[[str, bytes], Any],
) -> None:
    """Internally bind the exact catalog/profile/license resource graph."""
    validate_catalog_v5(catalog_value)
    catalog = require_object(catalog_value)
    expected: dict[str, tuple[str, str, str, str]] = {}
    for field, digest_field, schema_id in (
        (
            "system_requirement_profiles",
            "manifest_sha256",
            "kilix.content.system-requirements/v1",
        ),
        ("toolchain_profiles", "profile_sha256", "kilix.content.toolchain-profile/v1"),
        ("sandbox_profiles", "profile_sha256", "kilix.content.sandbox-profile/v1"),
    ):
        for entry in catalog[field]:
            path = entry["resource_path"]
            if path in expected:
                refuse("catalog profile paths collide across resource roles")
            expected[path] = (
                entry["id"],
                digest_field,
                entry[digest_field],
                schema_id,
            )
    license_path = f"licenses/{catalog['license_manifest_id']}.json"
    if license_path in expected:
        refuse("catalog license manifest path collides with a profile resource")
    if license_path not in resources or type(resources[license_path]) is not bytes:
        refuse("catalog resource bundle lacks its license manifest")
    for path, (
        identifier,
        digest_field,
        semantic_digest,
        schema_id,
    ) in expected.items():
        payload = resources.get(path)
        if type(payload) is not bytes:
            refuse("catalog resource bundle lacks a profile resource")
        validated = validate_json_resource(schema_id, payload)
        if not isinstance(validated, Mapping):
            refuse("catalog resource validator did not return immutable record data")
        if (
            validated.get("id") != identifier
            or validated.get(digest_field) != semantic_digest
        ):
            refuse("catalog profile authority diverges from validated resource data")
    license_record = validate_json_resource(
        "kilix.content.license-manifest/v1", resources[license_path]
    )
    if not isinstance(license_record, Mapping) or license_record.get(
        "release_id"
    ) != catalog.get("release_id"):
        refuse("catalog license manifest diverges from release authority")

    manifest_rows = {
        (entry["id"], entry["text_sha256"], entry["decision"])
        for entry in license_record["licenses"]
    }
    for collection in (catalog["packages"], catalog["contents"], catalog["assets"]):
        for installable in collection:
            for license_reference in installable["install"]["licenses"]:
                row = (
                    license_reference["id"],
                    license_reference["text_sha256"],
                    license_reference["decision"],
                )
                if row not in manifest_rows:
                    refuse("catalog license reference is not exact manifest authority")

    text_paths = {entry["path"] for entry in license_record["licenses"]}
    if license_path in text_paths or set(expected) & text_paths:
        refuse("catalog resource paths collide across data roles")
    expected_paths = set(expected) | {license_path} | text_paths
    if set(resources) != expected_paths:
        refuse("catalog resource bundle is missing data or contains extras")
    _validate_license_text_bundle(
        license_record, {path: resources[path] for path in text_paths}
    )


def _validate_license_text_bundle(
    manifest: Any, resources: Mapping[str, bytes]
) -> None:
    if not isinstance(manifest, Mapping):
        refuse("license manifest is not validated record data")
    manifest_value = manifest
    if manifest_value.get("schema") != "kilix.content.license-manifest/v1":
        refuse("license manifest schema is not frozen")
    licenses = manifest_value.get("licenses")
    if not isinstance(licenses, (list, tuple)):
        refuse("license manifest rows are not validated record data")
    expected = {
        entry["path"]: entry["text_sha256"]
        for entry in licenses
        if isinstance(entry, Mapping)
    }
    if len(expected) != len(licenses):
        refuse("license manifest rows are not validated record data")
    if set(resources) != set(expected):
        refuse("license text bundle is missing data or contains extras")
    for path, digest in expected.items():
        payload = resources[path]
        if type(payload) is not bytes or hashlib.sha256(payload).hexdigest() != digest:
            refuse("license text bundle contains a digest mismatch")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            refuse("license text is not valid UTF-8")
        if not text or "\x00" in text or unicodedata.normalize("NFC", text) != text:
            refuse("license text is not canonical UTF-8")


__all__ = [
    "DEPENDENCY_ROLES",
    "LICENSE_DECISIONS",
    "SOURCE_KINDS",
    "validate_authority_binding",
    "validate_authorization_v2",
    "validate_catalog_v5",
    "validate_install_record",
    "validate_output_binding",
    "validate_source",
]
