"""Read the SR-4 changed-text marker off a rendered first-use screen.

kilix-license prints the block immediately before the section whose text
changed (kilix_license.changed.changed_block). Tests read it back from the
screen, so they pin what a user sees rather than an internal call.
"""

from __future__ import annotations

CHANGED_HEADER = "=== changed since your last acceptance ==="


def changed_block(screen: bytes) -> list[str]:
    """The marker block's lines, or [] when the screen carries no marker."""
    text = screen.decode("utf-8")
    if CHANGED_HEADER not in text:
        return []
    lines = text.splitlines()
    start = lines.index(CHANGED_HEADER)
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("=== "):
            break
        block.append(line)
    return block


def marker_lines(
    section: str,
    identity: str,
    accepted: tuple[str, ...],
    under: tuple[str, ...],
    shown: str,
) -> list[str]:
    """The block kilix-license must print for one changed bound text."""
    return [
        CHANGED_HEADER,
        f"changed: {section}",
        f"text identity: {identity}",
        *[f"accepted sha256: {digest}" for digest in accepted],
        f"accepted under: {', '.join(under)}",
        f"shown sha256: {shown}",
        "The text below differs from the text you accepted before. "
        "Your earlier acceptance does not cover it.",
    ]
