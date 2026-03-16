#!/usr/bin/env python3
"""
embed-fonts.py — Embeds Share Tech Mono and VT323 as base64 into chat.html
Run once: python3 embed-fonts.py
No dependencies beyond Python stdlib + urllib.
"""

import base64
import re
import sys
import urllib.request
from pathlib import Path

HTML_FILE = Path("app.css")

FONTS = [
    {
        "family": "Share Tech Mono",
        "weight": "400",
        "style":  "normal",
        # Direct woff2 from Google Fonts static CDN (stable URL, OFL licensed)
        "url": "https://fonts.gstatic.com/s/sharetechmono/v15/J7aHnp1uDWRBEqV98dVQztYldFc7pAsEIc3Xew.woff2",
    },
    {
        "family": "VT323",
        "weight": "400",
        "style":  "normal",
        "url": "https://fonts.gstatic.com/s/vt323/v17/pxiKyp0ihIEF2hsYHpT2dkNE.woff2",
    },
]

STUB_START = "/* Stub @font-face blocks — replaced by embed-fonts.py */"
STUB_END   = "/* ─── VARIABLES ───────────────────────────────────── */"

def fetch_font(url: str) -> bytes:
    print(f"  Fetching {url} ...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    print(f"{len(data):,} bytes")
    return data

def make_face(font: dict, data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    return (
        f"@font-face {{\n"
        f"  font-family: '{font['family']}';\n"
        f"  font-style: {font['style']};\n"
        f"  font-weight: {font['weight']};\n"
        f"  font-display: swap;\n"
        f"  src: url('data:font/woff2;base64,{b64}') format('woff2');\n"
        f"}}"
    )

def main():
    if not HTML_FILE.exists():
        sys.exit(f"Error: {HTML_FILE} not found. Run this script in the same directory as chat.html.")

    print("CIPHER//NET font embedder")
    print("=" * 40)

    faces = []
    for font in FONTS:
        try:
            data = fetch_font(font["url"])
            faces.append(make_face(font, data))
        except Exception as e:
            sys.exit(f"\nFailed to fetch {font['family']}: {e}")

    replacement = "\n".join(faces) + "\n\n" + STUB_END

    html = HTML_FILE.read_text(encoding="utf-8")

    # Replace everything between STUB_START and STUB_END (inclusive)
    pattern = re.escape(STUB_START) + r".*?" + re.escape(STUB_END)
    new_html, n = re.subn(pattern, replacement, html, flags=re.DOTALL)

    if n == 0:
        sys.exit("Error: Could not find the font stub block in chat.html.\n"
                 "Has the file already been embedded, or was it modified?")

    HTML_FILE.write_text(new_html, encoding="utf-8")

    total_kb = sum(
        len(base64.b64encode(urllib.request.urlopen(
            urllib.request.Request(f["url"], headers={"User-Agent":"Mozilla/5.0"})
        ).read())) for f in []  # already fetched above, just report from faces
    )

    print(f"\n✓ Embedded {len(faces)} fonts into {HTML_FILE}")
    print(f"  Fonts are now fully offline — no external requests made by the page.")
    print(f"\nNote: the HTML file will be larger (~200–400 KB). This is expected.")

if __name__ == "__main__":
    main()
