"""Tracked-tree scan for model-weight suffixes, magics, and catalog digests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ALWAYS_SUFFIXES = (
    ".gguf",
    ".ggml",
    ".safetensors",
    ".onnx",
    ".pt",
    ".pth",
    ".ckpt",
    ".mdl",
    ".tflite",
    ".th",
    ".fst",
)
SIZE_GATED_SUFFIXES = (
    ".bin",
    ".npy",
    ".npz",
    ".pkl",
    ".pb",
    ".h5",
    ".engine",
    ".plan",
    ".ot",
)
SIZE_GATE_BYTES = 1024 * 1024
GGUF_MAGIC = b"GGUF"
GGML_MAGIC = b"ggml"
GGML_MAGIC_REV = b"lmgg"
# OpenFst kFstMagicNumber 2125659606 (0x7EB2FDD6), little-endian d6 fd b2 7e.
FST_MAGIC = b"\xd6\xfd\xb2\x7e"


@dataclass(frozen=True)
class WeightFinding:
    path: str
    reason: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout:
        return [
            root / Path(os.fsdecode(item))
            for item in result.stdout.split(b"\0")
            if item
        ]
    files: list[Path] = []
    skip = {".git", ".venv", "dist", "build", "__pycache__"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in skip and not name.endswith(".egg-info")
        ]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def load_catalog_digests(path: Path) -> tuple[str, frozenset[str]]:
    text = path.read_text(encoding="utf-8")
    digests: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(stripped) != 64 or any(ch not in "0123456789abcdef" for ch in stripped):
            raise ValueError(f"catalog digest list has a non-digest line: {stripped!r}")
        digests.append(stripped)
    return text, frozenset(digests)


def _suffix_hit(path: Path, size: int) -> str | None:
    name = path.name.lower()
    for suffix in ALWAYS_SUFFIXES:
        if name.endswith(suffix):
            return f"weight-suffix:{suffix}"
    if size >= SIZE_GATE_BYTES:
        for suffix in SIZE_GATED_SUFFIXES:
            if name.endswith(suffix):
                return f"weight-suffix-size:{suffix}"
    return None


def _magic_hit(head: bytes) -> str | None:
    if head.startswith(GGUF_MAGIC):
        return "magic:GGUF"
    if head.startswith(GGML_MAGIC) or head.startswith(GGML_MAGIC_REV):
        return "magic:ggml"
    if head.startswith(FST_MAGIC):
        return "magic:fst"
    if len(head) >= 16:
        length = int.from_bytes(head[:8], "little")
        rest = head[8:]
        if 2 <= length <= 100_000_000 and rest.startswith(b"{"):
            if b'"dtype"' in rest or b"__metadata__" in rest:
                return "magic:safetensors"
    return None


def generated_catalog_text(root: Path) -> str:
    generator = root / "tools" / "regenerate_catalog_digests.py"
    result = subprocess.run(
        [sys.executable, str(generator), "--stdout"],
        check=True,
        capture_output=True,
        cwd=root,
    )
    return result.stdout.decode("utf-8")


def catalog_matches_generator(root: Path, catalog_digest_path: Path) -> bool:
    return catalog_digest_path.read_text(encoding="utf-8") == generated_catalog_text(root)


def _skip_catalog_digest_path(rel: str) -> bool:
    """Licence text store is not a weight blob (C1-VERIFY F-01)."""
    normalized = rel.replace("\\", "/")
    return "kilix-license" in normalized and "/data/texts/" in f"/{normalized}"


def scan_tree(root: Path, catalog_digest_path: Path) -> list[WeightFinding]:
    _text, catalog = load_catalog_digests(catalog_digest_path)
    findings: list[WeightFinding] = []
    for path in tracked_paths(root):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        size = path.stat().st_size
        suffix = _suffix_hit(path, size)
        if suffix:
            findings.append(WeightFinding(rel, suffix))
        head = path.read_bytes()[:256]
        magic = _magic_hit(head)
        if magic:
            findings.append(WeightFinding(rel, magic))
        if _skip_catalog_digest_path(rel):
            continue
        digest = sha256_file(path)
        if digest in catalog:
            findings.append(WeightFinding(rel, f"catalog-digest:{digest}"))
    return findings
