"""Shields-style SVG badge, self-contained (no external service)."""
from __future__ import annotations

from html import escape

GRADE_HEX = {"A": "#2f9e44", "B": "#4b7bec", "C": "#e8a13a", "D": "#e5622a", "E": "#e5484d", "F": "#c92a2a"}


def _width(text: str) -> int:
    return 7 * len(text) + 14


def badge(label: str, message: str, color: str) -> str:
    lw, mw = _width(label), _width(message)
    total = lw + mw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img"
 aria-label="{escape(label)}: {escape(message)}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
  <stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{mw}" height="20" fill="{color}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="15" fill="#010101" fill-opacity=".3">{escape(label)}</text>
    <text x="{lw/2}" y="14">{escape(label)}</text>
    <text x="{lw + mw/2}" y="15" fill="#010101" fill-opacity=".3">{escape(message)}</text>
    <text x="{lw + mw/2}" y="14">{escape(message)}</text>
  </g>
</svg>'''


def grade_badge(letter: str) -> str:
    return badge("security", f"grade {letter}", GRADE_HEX.get(letter, "#999"))
