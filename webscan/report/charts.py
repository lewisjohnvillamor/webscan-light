"""Self-contained inline-SVG chart builders.

No JavaScript and no external libraries, so every chart renders identically in
the browser, in the headless-Chromium PDF, and offline. Colours are supplied by
the caller via CSS custom properties so the charts follow the page theme.
"""
from __future__ import annotations

import math
from html import escape


def donut(
    value: int,
    total: int,
    *,
    color_var: str,
    label: str,
    size: int = 132,
    stroke: int = 11,
) -> str:
    """A single ring gauge with the value centred, matching the reference UI.

    The ring fills in proportion to ``value / total`` (share of all findings),
    so a dominant severity visibly dominates the row.
    """
    radius = (size - stroke) / 2
    circumference = 2 * math.pi * radius
    fraction = 0.0 if total <= 0 else max(0.0, min(1.0, value / total))
    # A hair of arc even at zero reads as "empty ring" rather than "no ring".
    dash = circumference * fraction
    gap = circumference - dash
    cx = cy = size / 2
    active = value > 0
    center_class = "gauge-value" + ("" if active else " gauge-value-muted")
    return f"""
<figure class="gauge" role="img" aria-label="{escape(label)}: {value} of {total}">
  <svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">
    <circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none"
            stroke="var(--track)" stroke-width="{stroke}"/>
    <circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none"
            stroke="var({color_var})" stroke-width="{stroke}" stroke-linecap="round"
            stroke-dasharray="{dash:.2f} {gap:.2f}"
            transform="rotate(-90 {cx} {cy})"
            style="transition:stroke-dasharray .9s cubic-bezier(.22,1,.36,1)"/>
    <text x="{cx}" y="{cy}" class="{center_class}" text-anchor="middle"
          dominant-baseline="central">{value}</text>
  </svg>
  <figcaption class="gauge-label" style="color:var({color_var})">{escape(label)}</figcaption>
</figure>"""


def stacked_bar(segments: list[tuple[str, int, str]], *, height: int = 14) -> str:
    """A single horizontal bar split into coloured segments.

    ``segments`` is a list of (label, value, color_var). Zero-value segments are
    dropped so the bar shows only what is present.
    """
    present = [(label, value, var) for label, value, var in segments if value > 0]
    total = sum(value for _, value, _ in present)
    if total <= 0:
        return '<div class="stack empty">No findings</div>'
    cells = []
    for label, value, var in present:
        pct = 100 * value / total
        cells.append(
            f'<span class="stack-seg" style="width:{pct:.3f}%;background:var({var})" '
            f'title="{escape(label)}: {value}"></span>'
        )
    legend = " ".join(
        f'<span class="stack-key"><i style="background:var({var})"></i>'
        f'{escape(label)} <b>{value}</b></span>'
        for label, value, var in present
    )
    return (
        f'<div class="stack" style="height:{height}px">{"".join(cells)}</div>'
        f'<div class="stack-legend">{legend}</div>'
    )


def hbars(rows: list[tuple[str, int]], *, color_var: str = "--accent", max_rows: int = 10) -> str:
    """A compact horizontal bar chart for category counts (e.g. OWASP)."""
    rows = [(label, value) for label, value in rows if value > 0]
    rows.sort(key=lambda item: item[1], reverse=True)
    rows = rows[:max_rows]
    if not rows:
        return ""
    peak = max(value for _, value in rows)
    out = ['<div class="hbars">']
    for label, value in rows:
        pct = 100 * value / peak
        out.append(
            f'<div class="hbar-row"><span class="hbar-label" title="{escape(label)}">'
            f'{escape(label)}</span>'
            f'<span class="hbar-track"><span class="hbar-fill" '
            f'style="width:{pct:.2f}%;background:var({color_var})"></span></span>'
            f'<span class="hbar-val">{value}</span></div>'
        )
    out.append("</div>")
    return "".join(out)
