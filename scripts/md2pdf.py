"""Render a markdown doc to a phone-readable PDF via headless Chrome or Edge.

Page is A5 rather than A4 so the text is large enough to read on a phone without
pinch-zooming, and each top-level section starts on a new page for navigation.
The hand-written contents list becomes tappable internal links.

Usage:  python scripts/md2pdf.py docs/HOW-IT-WORKS.md docs/HOW-IT-WORKS.pdf
Needs:  pip install markdown   (and Chrome or Edge installed)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import markdown

_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]


def find_browser() -> str:
    """First Chrome/Edge we can find: $BROWSER_BIN, then PATH, then known locations."""
    if (env := os.environ.get("BROWSER_BIN")) and Path(env).exists():
        return env
    for name in ("chrome", "google-chrome", "chromium", "msedge"):
        if found := shutil.which(name):
            return found
    for path in _CANDIDATES:
        if Path(path).exists():
            return path
    raise SystemExit("No Chrome or Edge found. Set BROWSER_BIN to the executable.")

CSS = """
@page { size: A5; margin: 12mm 11mm 13mm; }

* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  font: 10.5pt/1.55 Georgia, "Times New Roman", serif;
  color: #16161c; margin: 0;
  hyphens: auto; -webkit-hyphens: auto;
}

/* --- headings ------------------------------------------------------------ */
h1, h2, h3, h4 {
  font-family: "Segoe UI", Arial, sans-serif;
  color: #0d0d13; line-height: 1.2; margin: 0;
  page-break-after: avoid; break-after: avoid;
}
h1 { font-size: 21pt; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 4mm; }
h2 {
  font-size: 14pt; font-weight: 700; letter-spacing: -0.01em;
  margin: 0 0 3mm; padding-bottom: 1.6mm;
  border-bottom: 2px solid #ffe600;
  page-break-before: always; break-before: page;
}
h1 + h2, h2:first-of-type { page-break-before: avoid; break-before: auto; }
h3 { font-size: 11pt; font-weight: 700; margin: 5mm 0 1.6mm; }
h4 { font-size: 10pt; font-weight: 700; margin: 4mm 0 1.5mm; }

p, ul, ol { margin: 0 0 2.6mm; }
ul, ol { padding-left: 5.2mm; }
li { margin-bottom: 1.1mm; }
li > p { margin-bottom: 1.2mm; }
strong { color: #000; }
a { color: #16161c; text-decoration: none; border-bottom: 0.4pt solid #b8b8c4; }
hr { border: 0; border-top: 0.6pt solid #dcdce4; margin: 5mm 0; }

/* --- code ---------------------------------------------------------------- */
code {
  font-family: Consolas, "Courier New", monospace; font-size: 8.6pt;
  background: #f3f3f7; border: 0.4pt solid #e2e2ea;
  padding: 0.3mm 0.9mm; border-radius: 1pt;
}
pre {
  background: #f7f7fa; border: 0.5pt solid #dcdce4; border-left: 2pt solid #ffe600;
  padding: 2.4mm 3mm; margin: 0 0 3mm; overflow: hidden;
  page-break-inside: avoid; break-inside: avoid;
}
pre code {
  font-size: 8pt; line-height: 1.45; background: none; border: 0; padding: 0;
  white-space: pre-wrap; word-break: break-word;
}

/* --- tables -------------------------------------------------------------- */
table {
  width: 100%; border-collapse: collapse; margin: 0 0 3.4mm;
  font-family: "Segoe UI", Arial, sans-serif; font-size: 8.2pt; line-height: 1.38;
}
th, td { text-align: left; padding: 1.3mm 1.6mm; border-bottom: 0.4pt solid #e2e2ea; vertical-align: top; }
thead th {
  font-size: 7.2pt; text-transform: uppercase; letter-spacing: 0.06em;
  color: #55555f; background: #f3f3f7; border-bottom: 0.8pt solid #c9c9d4;
}
tbody tr { page-break-inside: avoid; break-inside: avoid; }
td code, th code { font-size: 7.6pt; }

/* --- callouts ------------------------------------------------------------ */
blockquote {
  margin: 0 0 3mm; padding: 2.4mm 3mm;
  background: #fffbe0; border: 0.5pt solid #e8d97a; border-left: 2.5pt solid #d9b800;
  page-break-inside: avoid; break-inside: avoid;
}
blockquote p { margin: 0; font-size: 9.6pt; }

/* --- contents list ------------------------------------------------------- */
.toc { font-family: "Segoe UI", Arial, sans-serif; font-size: 9.4pt; }
.toc a { border: 0; }
"""


def slugify(text: str) -> str:
    """Match the anchor style GitHub uses, so the hand-written contents links work."""
    s = text.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"[\s_]+", "-", s).strip("-")


def add_heading_ids(html: str) -> str:
    def repl(m: re.Match) -> str:
        level, inner = m.group(1), m.group(2)
        text = re.sub(r"<[^>]+>", "", inner)
        return f'<h{level} id="{slugify(text)}">{inner}</h{level}>'
    return re.sub(r"<h([1-4])>(.*?)</h\1>", repl, html, flags=re.S)


def main() -> int:
    src = Path(sys.argv[1])
    out = Path(sys.argv[2])
    text = src.read_text(encoding="utf-8")

    body = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "sane_lists", "attr_list"],
        output_format="html5",
    )
    body = add_heading_ids(body)
    # the hand-written contents block is an <ol> right after the "Contents" line
    body = body.replace("<p><strong>Contents</strong></p>\n<ol>", '<p><strong>Contents</strong></p>\n<ol class="toc">', 1)

    html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{src.stem}</title><style>{CSS}</style></head><body>{body}</body></html>"
    )
    tmp = out.with_suffix(".render.html")
    tmp.write_text(html, encoding="utf-8")

    url = "file:///" + str(tmp.resolve()).replace("\\", "/")
    cmd = [
        find_browser(), "--headless=new", "--disable-gpu", "--no-sandbox",
        "--no-pdf-header-footer",
        # builds PDF bookmarks from the headings -- this is the section list a
        # phone PDF reader shows, and the only practical way to navigate 35 pages
        "--generate-pdf-document-outline",
        "--virtual-time-budget=5000",
        f"--print-to-pdf={out.resolve()}", url,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if not out.exists():
        print("chrome failed:\n", proc.stdout, proc.stderr)
        return 1
    tmp.unlink(missing_ok=True)
    print(f"wrote {out}  ({out.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
