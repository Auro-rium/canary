"""Minimal text-only PDF writer (WP8 reports), so PDF export needs no extra dependency.

One standard Type1 font (Helvetica, WinAnsi), monospaced-ish wrapping, US Letter
pages. Characters outside Latin-1 are replaced with ``?``. Good enough for a
plain report download; it is not a typesetting engine.
"""

from __future__ import annotations

import textwrap

PAGE_W, PAGE_H = 612, 792
MARGIN = 50
FONT_SIZE = 10
LEADING = 13
WRAP = 100
LINES_PER_PAGE = (PAGE_H - 2 * MARGIN) // LEADING


def _escape(line: str) -> str:
    line = line.encode("latin-1", "replace").decode("latin-1")
    return line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines() or [""]:
        raw = raw.expandtabs(4)
        out.extend(textwrap.wrap(raw, WRAP, replace_whitespace=False, drop_whitespace=False) or [""])
    return out


def render_text_pdf(text: str, title: str = "Canary report") -> bytes:
    lines = _wrap(text)
    pages = [lines[i:i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)] or [[]]

    objects: list[bytes] = []  # object n is objects[n-1]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")  # pages, filled below
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    info_title = _escape(title)
    objects.append(f"<< /Title ({info_title}) /Producer (Canary) >>".encode("latin-1"))
    kids = []
    for page_lines in pages:
        ops = [f"BT /F1 {FONT_SIZE} Tf {LEADING} TL {MARGIN} {PAGE_H - MARGIN} Td"]
        for line in page_lines:
            ops.append(f"({_escape(line)}) Tj T*")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        content_no = len(objects)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_no} 0 R >>".encode()
        )
        kids.append(len(objects))
    objects[1] = (
        f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()
    )

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, xref,
    )
    return bytes(out)
