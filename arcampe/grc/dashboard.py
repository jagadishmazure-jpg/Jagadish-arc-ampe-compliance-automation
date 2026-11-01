"""Trust dashboard (static HTML): framework readiness cards, business units, SOC 2 path, evidence statuses.

Self-contained HTML with inline SVG; no scripts, no external assets. Numbers come from reporting.metrics(),
which reads only the synthetic data in this repo.
"""
from __future__ import annotations

from html import escape

from . import svgchart


def to_html(m: dict | None = None) -> str:
    from . import reporting
    m = m or reporting.metrics()
    ai = m["ai_policy"]
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>Trust dashboard</title>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        "</head><body style='font-family:Arial;margin:24px'>",
        f"<h1>Trust dashboard - {escape(m['entity'])}</h1>",
        f"<p style='color:#a00'>Synthetic data. As of {escape(m['as_of'])}. Not a real system.</p>",
        "<h2>Framework readiness</h2>",
        ("<p>Each ring = controls mapped to that framework that are tested and passing, over all mapped controls. "
         "Mappings other than NIST 800-53 are approximate (author-built).</p>"),
        svgchart.cards(m["frameworks"], per_row=6, size=100),
        "<h2>Business units</h2>",
        svgchart.hbar([(r["name"], r["readiness_pct"]) for r in m["business_units"]], 100, "%"),
        (f"<h2>SOC 2 guided path</h2><p><b>{escape(m['soc2']['label'])}</b> "
         f"({m['soc2']['in_progress']} in progress, {m['soc2']['to_do']} to do)</p>"),
        "<h2>Evidence status</h2>",
        svgchart.hbar(list(m["evidence"]["counts"].items())),
        (f"<h2>AI Development and Evaluation Policy</h2><p>{ai['ready_parts']} of {ai['of']} parts ready "
         f"({'Ready' if ai['ready'] else 'Not ready'})</p>"),
        "</body></html>",
    ]
    return "\n".join(parts)
