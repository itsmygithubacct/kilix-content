#!/usr/bin/env python3
"""check-deb.py DEB : kilix-content keeps the checkout layout under /usr/share."""

import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    print(f"check-deb: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check-deb.py DEB")
    deb = Path(sys.argv[1])
    fields = subprocess.run(
        ["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"],
        check=True, capture_output=True, text=True).stdout
    for needle in ("Package: kilix-content\n", "Version: 0.4.0+packaging1\n", "Architecture: all\n"):
        if needle not in fields:
            fail(f"unexpected fields:\n{fields}")
    with tempfile.TemporaryDirectory(prefix="kilix-content-deb.") as raw:
        root = Path(raw)
        subprocess.run(["dpkg-deb", "-x", str(deb), str(root)], check=True)
        share = root / "usr/share/kilix-content"
        if not (share / "src/kilix_content/__init__.py").is_file():
            fail("catalog missing")
        if not (share / "third_party/kilix-license/src/kilix_license/__init__.py").is_file():
            fail("licence library missing")
        if (share / "tests").exists():
            fail("tests were packaged")
        if any(share.rglob("*.onnx")) or any(share.rglob("*.gguf")):
            fail("weights were packaged")
        code = (
            "import sys\n"
            f"sys.path.insert(0, {str(share / 'src')!r})\n"
            "import kilix_content\n"
            "from kilix_content.paths import license_src\n"
            "print(kilix_content.__file__)\n"
            "print(license_src())\n"
        )
        ran = subprocess.run(["python3", "-c", code], check=True, capture_output=True, text=True)
        if "kilix_content" not in ran.stdout or "kilix-license" not in ran.stdout:
            fail(f"import probe failed:\n{ran.stdout}")
    print("check-deb: passed")


if __name__ == "__main__":
    main()
