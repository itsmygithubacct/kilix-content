#!/usr/bin/env python3
"""Tie third_party/kilix-license/ to the pinned kilix-license commit.

third_party/kilix-license.objects.json holds the pinned commit object and the
git tree objects on every vendored path. The suite (tests/test_contracts.py)
checks offline that the pin hashes to that commit, the commit to its root
tree, each tree to its entries, and every vendored file to its blob id. So
the vendored bytes are exactly what `git archive <pin>` yields for those
paths, and neither a file nor this record can be changed alone.

With --repo PATH (a kilix-license repository holding the pin):
  --check  (default) fail unless the record equals the repository's objects
           and every vendored file equals its `git archive <pin>` member,
           with no file missing or extra.
  --write  regenerate the record from the repository. It never re-vendors.
  --repin NEW --old OLD
           move the pin to NEW and re-vendor from `git archive NEW`. The pin
           file must hold OLD, exactly once, and the vendored tree must still
           hash up to OLD, so nothing is replaced on a guess. Vendored bytes
           only ever come from `git archive`, never from a checkout, and the
           pin file and the objects record are written here, never by hand.

Without --repo, --check verifies the recorded chain against the tree only.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "third_party" / "kilix-license"
PIN_FILE = ROOT / "third_party" / "kilix-license.pin"
OBJECTS_FILE = ROOT / "third_party" / "kilix-license.objects.json"
SCHEMA = "kilix-content.vendored-git-objects/v1"
# Top-level entries of the kilix-license tree that are deliberately not vendored.
EXCLUDED = (
    ".gitignore",
    ".python-version",
    "Makefile",
    "PUBLICATION.md",
    "tests",
    "tools",
    "uv.lock",
)
TREE_MODE = "40000"
FILE_MODES = ("100644", "100755")


class VendorError(Exception):
    pass


def git_oid(kind: str, body: bytes) -> str:
    header = f"{kind} {len(body)}\0".encode("ascii")
    return hashlib.sha1(header + body).hexdigest()


def tree_bytes(entries: list[list[str]]) -> bytes:
    return b"".join(
        mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)
        for mode, name, oid in entries
    )


def parse_tree(raw: bytes) -> list[list[str]]:
    entries: list[list[str]] = []
    index = 0
    while index < len(raw):
        space = raw.index(b" ", index)
        nul = raw.index(b"\0", space)
        entries.append(
            [
                raw[index:space].decode("ascii"),
                raw[space + 1 : nul].decode("utf-8"),
                raw[nul + 1 : nul + 21].hex(),
            ]
        )
        index = nul + 21
    return entries


def read_pin() -> str:
    return PIN_FILE.read_text(encoding="utf-8").strip()


def chain_blobs(objects: dict) -> dict[str, str]:
    """Verify pin -> commit -> trees; return vendored path -> blob id."""
    if objects.get("schema") != SCHEMA:
        raise VendorError("objects record has an unknown schema")
    pin = read_pin()
    if objects.get("pin") != pin:
        raise VendorError("objects record names a different pin")
    if tuple(objects.get("excluded_top_level", ())) != EXCLUDED:
        raise VendorError("objects record excludes different top-level entries")
    commit = objects["commit"].encode("utf-8")
    if git_oid("commit", commit) != pin:
        raise VendorError("recorded commit object does not hash to the pin")
    first = commit.split(b"\n", 1)[0].decode("ascii")
    if not first.startswith("tree "):
        raise VendorError("recorded commit object has no tree line")
    trees = objects["trees"]
    blobs: dict[str, str] = {}
    seen_excluded: list[str] = []

    def walk(oid: str, prefix: str) -> None:
        entries = trees.get(oid)
        if entries is None:
            raise VendorError(f"tree {oid} for {prefix or '/'} is not recorded")
        if git_oid("tree", tree_bytes(entries)) != oid:
            raise VendorError(f"recorded tree {prefix or '/'} does not hash to {oid}")
        for mode, name, child in entries:
            path = prefix + name
            if not prefix and name in EXCLUDED:
                seen_excluded.append(name)
            elif mode == TREE_MODE:
                walk(child, path + "/")
            elif mode in FILE_MODES:
                blobs[path] = child
            else:
                raise VendorError(f"{path} has git mode {mode}: not a regular file")

    walk(first[len("tree ") :], "")
    if sorted(seen_excluded) != sorted(EXCLUDED):
        raise VendorError("an excluded top-level entry is not in the pinned tree")
    return blobs


def vendored_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(VENDORED.rglob("*")):
        relative = path.relative_to(VENDORED)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise VendorError(f"vendored {relative} is a symlink")
        if path.is_file():
            files[relative.as_posix()] = path.read_bytes()
    return files


def check_chain() -> dict[str, str]:
    objects = json.loads(OBJECTS_FILE.read_text(encoding="utf-8"))
    blobs = chain_blobs(objects)
    files = vendored_files()
    if sorted(files) != sorted(blobs):
        missing = sorted(set(blobs) - set(files))
        extra = sorted(set(files) - set(blobs))
        raise VendorError(f"vendored tree differs: missing {missing}, extra {extra}")
    for path, oid in blobs.items():
        if git_oid("blob", files[path]) != oid:
            raise VendorError(f"vendored {path} is not the pinned blob {oid}")
    return blobs


def _git(repo: str, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", repo, "--no-optional-locks", *args],
        check=True,
        capture_output=True,
    ).stdout


def objects_from_repo(repo: str) -> dict:
    pin = read_pin()
    commit = _git(repo, "cat-file", "commit", pin)
    first = commit.split(b"\n", 1)[0].decode("ascii")
    trees: dict[str, list[list[str]]] = {}

    def walk(oid: str, top: bool) -> None:
        entries = parse_tree(_git(repo, "cat-file", "tree", oid))
        trees[oid] = entries
        for mode, name, child in entries:
            if top and name in EXCLUDED:
                continue
            if mode == TREE_MODE:
                walk(child, False)

    walk(first[len("tree ") :], True)
    return {
        "commit": commit.decode("utf-8"),
        "excluded_top_level": list(EXCLUDED),
        "pin": pin,
        "schema": SCHEMA,
        "trees": trees,
    }


def render(objects: dict) -> str:
    lines = ["{"]
    for key in ("commit", "excluded_top_level", "pin", "schema"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(objects[key], ensure_ascii=False)},")
    lines.append('  "trees": {')
    tree_items = sorted(objects["trees"].items())
    for position, (oid, entries) in enumerate(tree_items):
        lines.append(f"    {json.dumps(oid)}: [")
        for index, entry in enumerate(entries):
            comma = "," if index < len(entries) - 1 else ""
            lines.append(f"      {json.dumps(entry, ensure_ascii=False)}{comma}")
        lines.append("    ]" + ("," if position < len(tree_items) - 1 else ""))
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def archive_members(repo: str, rev: str | None = None) -> dict[str, tuple[bytes, bool]]:
    """path -> (bytes, executable) for every file in `git archive <rev>`."""
    data = _git(repo, "archive", "--format=tar", rev or read_pin())
    members: dict[str, tuple[bytes, bool]] = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise VendorError(f"archive member {member.name} is a link")
            if member.isfile():
                handle = archive.extractfile(member)
                assert handle is not None
                members[member.name] = (handle.read(), bool(member.mode & 0o111))
    return members


def check_repo(repo: str) -> str:
    expected = render(objects_from_repo(repo))
    if OBJECTS_FILE.read_text(encoding="utf-8") != expected:
        raise VendorError("objects record differs from the repository's pinned objects")
    blobs = check_chain()
    archive = {path: body for path, (body, _x) in archive_members(repo).items()}
    wanted = {
        path: body
        for path, body in archive.items()
        if path.split("/", 1)[0] not in EXCLUDED
    }
    files = vendored_files()
    if sorted(files) != sorted(wanted):
        raise VendorError("vendored paths differ from git archive of the pin")
    for path, body in wanted.items():
        if files[path] != body:
            raise VendorError(f"vendored {path} differs from git archive of the pin")
        if git_oid("blob", body) != blobs[path]:
            raise VendorError(f"git archive member {path} is not the recorded blob")
    listing = "".join(
        f"{hashlib.sha256(files[path]).hexdigest()}  {path}\n" for path in sorted(files)
    )
    return (
        f"{len(files)} vendored files equal git archive {read_pin()} "
        f"(archive has {len(archive)} files; {len(archive) - len(wanted)} under "
        f"excluded top-level entries); sha256sum listing digest "
        f"{hashlib.sha256(listing.encode('utf-8')).hexdigest()}"
    )


def _require_hex40(rev: str) -> str:
    if len(rev) != 40 or any(character not in "0123456789abcdef" for character in rev):
        raise VendorError(f"{rev} is not a 40-hex commit id")
    return rev


def _commit_id(repo: str, rev: str) -> str:
    _require_hex40(rev)
    resolved = _git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()
    if resolved != rev:
        raise VendorError(f"{rev} does not name a commit in {repo}")
    return resolved


def repin(repo: str, new_pin: str, old_pin: str) -> str:
    """Move the pin to new_pin and re-vendor from `git archive new_pin`.

    The old-value guard holds the whole operation: the pin file must read
    old_pin, exactly once, and the vendored tree must still hash up to it. So
    a re-pin can only ever replace the bytes it names.
    """
    # Everything that can be judged without touching the repository is judged
    # first, so a guard never rests on a repository being readable.
    _require_hex40(new_pin)
    _require_hex40(old_pin)
    text = PIN_FILE.read_text(encoding="utf-8")
    current = text.strip()
    if text.count(old_pin) != 1:
        raise VendorError(
            f"old-value guard failed: {old_pin} occurs {text.count(old_pin)} times in "
            f"{PIN_FILE.relative_to(ROOT)}"
        )
    if current != old_pin:
        raise VendorError(f"old-value guard failed: pin is {current}, expected {old_pin}")
    if new_pin == old_pin:
        raise VendorError(f"already pinned to {new_pin}")
    before = check_chain()  # the tree on disk is still exactly the old pin
    _commit_id(repo, old_pin)
    _commit_id(repo, new_pin)
    members = archive_members(repo, new_pin)
    top_level = {name for _mode, name, _oid in parse_tree(_git(repo, "cat-file", "tree", new_pin))}
    missing = sorted(set(EXCLUDED) - top_level)
    if missing:
        raise VendorError(f"{new_pin} has no top-level entry {missing}")
    wanted = {
        path: value
        for path, value in members.items()
        if path.split("/", 1)[0] not in EXCLUDED
    }
    if not wanted:
        raise VendorError(f"git archive {new_pin} vendors no file")
    for path in sorted(VENDORED.rglob("*"), reverse=True):
        if "__pycache__" in path.relative_to(VENDORED).parts:
            continue
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    for path, (body, executable) in sorted(wanted.items()):
        destination = VENDORED / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        destination.chmod(0o755 if executable else 0o644)
    PIN_FILE.write_text(new_pin + "\n", encoding="utf-8")
    OBJECTS_FILE.write_text(render(objects_from_repo(repo)), encoding="utf-8")
    return (
        f"re-pinned {old_pin} -> {new_pin} ({len(before)} vendored files before, "
        f"{len(wanted)} after)\n{check_repo(repo)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--repo", help="kilix-license repository holding the pin")
    parser.add_argument("--old", help="the pin --repin must find in place")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--repin", help="commit to move the pin to, re-vendoring it")
    args = parser.parse_args(argv)
    try:
        if args.repin:
            if not args.repo:
                parser.error("--repin needs --repo")
            if not args.old:
                parser.error("--repin needs --old")
            print(repin(args.repo, args.repin, args.old))
        elif args.write:
            if not args.repo:
                parser.error("--write needs --repo")
            OBJECTS_FILE.write_text(render(objects_from_repo(args.repo)), encoding="utf-8")
            print(f"wrote {OBJECTS_FILE.relative_to(ROOT)}")
            print(check_repo(args.repo))
        elif args.repo:
            print(check_repo(args.repo))
        else:
            blobs = check_chain()
            print(f"{len(blobs)} vendored files hash up to pin {read_pin()}")
    except (VendorError, subprocess.CalledProcessError) as exc:
        print(f"vendored kilix-license: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
