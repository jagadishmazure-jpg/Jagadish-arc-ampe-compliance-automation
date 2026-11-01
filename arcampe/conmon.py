"""Continuous monitoring (CONMON) report in Markdown and a self-contained HTML dashboard.

Monthly cadence follows the AE CA-07 parameter (30 days). Numbers come from the synthetic run.
"""
from __future__ import annotations

import html

from . import ENTITY, TODAY, agent, assess, attest, poam
from .challenges import audit_readiness
from .platform import monitoring
from .risk import cyber


def metrics(findings=None) -> dict:
    findings = assess.run_all() if findings is None else findings
    items = poam.build(findings)
    from .integrations.connectors import collect_all

    ev = collect_all()
    alerts = monitoring.detect(monitoring.load_events())
    risks = cyber.top10(cyber.analyze(findings=findings))
    return {
        "as_of": TODAY,
        "assessment": assess.summary(findings),
        "poam": poam.summary(items),
        "attestations": attest.summary(attest.load()),
        "readiness": audit_readiness.readiness(findings, items, agent.load_approvals()),
        "vulnerabilities": monitoring.vulnerability_view(ev),
        "alerts": len(alerts),
        "top_risks": [(r["id"], r["threat"], r["ale"]["p90"], r["exceeds_appetite"]) for r in risks[:5]],
        "overdue_items": [i.row() for i in items if i.sla_status == "overdue"][:10],
    }


def to_markdown(m: dict) -> str:
    a, p, t = m["assessment"], m["poam"], m["attestations"]
    lines = [f"# CONMON report - {ENTITY} (synthetic) - {m['as_of']}", "",
             "| Metric | Value |", "|---|---|",
             f"| Findings (pass / fail) | {a['passed']} / {a['failed']} |",
             f"| Open POA&M items | {p['open']} |",
             f"| POA&M overdue | {p['by_sla']['overdue']} |",
             f"| Attestations current / due soon / overdue / missing | {t['current']} / {t['due_soon']} / "
             f"{t['overdue']} / {t['missing']} |",
             f"| Audit readiness score | {m['readiness']['score']} |",
             f"| Security alerts (simulated events) | {m['alerts']} |", "",
             "## POA&M by severity", "", "| Severity | Open |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in p["by_severity"].items()]
    lines += ["", "## Top risks (P90 annual loss, synthetic FAIR inputs)", "", "| ID | Threat | P90 | Over appetite |",
              "|---|---|---|---|"]
    lines += [f"| {i} | {th} | ${v:,.0f} | {'yes' if o else 'no'} |" for i, th, v, o in m["top_risks"]]
    lines += ["", "## Overdue POA&M items (first 10)", "", "| ID | Check | Resource | Severity | Due |",
              "|---|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['check_id']} | {r['resource']} | {r['severity']} | {r['due']} |"
              for r in m["overdue_items"]]
    return "\n".join(lines) + "\n"


def to_html(m: dict) -> str:
    a, p = m["assessment"], m["poam"]
    e = html.escape
    tiles = [("Pass", a["passed"]), ("Fail", a["failed"]), ("Open POA&M", p["open"]),
             ("Overdue", p["by_sla"]["overdue"]), ("Readiness", m["readiness"]["score"]), ("Alerts", m["alerts"])]
    tile_html = "".join(f'<div class="t"><b>{e(str(v))}</b><span>{e(k)}</span></div>' for k, v in tiles)
    total = max(1, p["open"])
    bars = "".join(f'<div class="bar"><span>{e(k)}</span><i style="width:{100 * v / total:.1f}%"></i>{v}</div>'
                   for k, v in p["by_severity"].items())
    rows = "".join(f"<tr><td>{e(r['id'])}</td><td>{e(r['check_id'])}</td><td>{e(r['resource'])}</td>"
                   f"<td>{e(r['severity'])}</td><td>{e(r['due'])}</td></tr>" for r in m["overdue_items"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>CONMON {e(m['as_of'])}</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1b}} .ts{{display:flex;gap:1rem;flex-wrap:wrap}}
.t{{border:1px solid #ccc;border-radius:8px;padding:1rem;min-width:7rem}} .t b{{font-size:1.6rem;display:block}}
.bar{{display:flex;align-items:center;gap:.5rem;margin:.3rem 0}} .bar span{{width:6rem}}
.bar i{{display:inline-block;height:1rem;background:#1f3864}} table{{border-collapse:collapse}}
td,th{{border:1px solid #ccc;padding:.3rem .6rem}} .note{{color:#666}}</style></head><body>
<h1>CONMON dashboard - {e(ENTITY)}</h1><p class="note">Synthetic data. As of {e(m['as_of'])}. Not a real system.</p>
<div class="ts">{tile_html}</div><h2>Open POA&amp;M by severity</h2>{bars}
<h2>Overdue items</h2><table><tr><th>ID</th><th>Check</th><th>Resource</th><th>Severity</th><th>Due</th></tr>
{rows}</table></body></html>
"""
