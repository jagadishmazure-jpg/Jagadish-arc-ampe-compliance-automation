"""Executive reporting: daily and weekly leadership emails with inline charts, plus PDF and CSV.

What it does by default: builds the report and WRITES FILES to out/reports/ (report.html, report.eml, report.pdf,
report.csv). It never sends. send() refuses unless (1) a config says enabled=true with a transport and recipients,
(2) the caller passes approved=True, and (3) a transport function is supplied by the caller. This repo ships no
transport, so nothing can leave the box from here.

Every number comes from the synthetic data in this repo. Labels say which numbers are measured on the synthetic
run, and which are simulated (trust-to-revenue). None are vendor claims.
"""
from __future__ import annotations

import csv
import io
import json
from email.message import EmailMessage
from email.utils import format_datetime
from html import escape

from .. import ENTITY, TODAY
from . import minipdf, svgchart

KINDS = ("daily", "weekly")
FROM = "grc-reports@lakehaven-hx.example"
DEFAULT_TO = ("leadership@lakehaven-hx.example",)

# Simulated: partner onboarding deals that waited on a security review (no real revenue data exists here).
TRUST_PIPELINE = (
    {"deal": "Partner insurer A", "value": 180_000, "security_review": "done", "days_in_review": 9},
    {"deal": "Partner insurer B", "value": 95_000, "security_review": "open", "days_in_review": 21},
    {"deal": "County health office", "value": 60_000, "security_review": "done", "days_in_review": 4},
    {"deal": "Navigator network", "value": 40_000, "security_review": "open", "days_in_review": 12},
)


class SendRefused(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------------- metrics
def metrics(today: str = TODAY) -> dict:
    from .. import assess, poam, resilience, supply_chain
    from ..integrations import mapper
    from ..integrations.connectors import collect_all
    from . import (
        access_review_import,
        ai_governance,
        ai_policy,
        evidence_status,
        frameworks,
        industry_packs,
        ownership,
        review,
        risk_registers,
        scanner_import,
        soc2_path,
        vendor_requests,
        workspaces,
    )

    by = assess.by_control()
    findings = assess.run_all()
    items = poam.build(findings)
    fw = frameworks.readiness(by)
    bu = workspaces.readiness(by)
    ev = evidence_status.summary(collect_all(), today=today)
    vend = [supply_chain.score(v, today) for v in supply_chain.load()]
    ar = access_review_import.summarize(access_review_import.load(), today)
    m = mapper.evaluate()
    rv = review.demo()
    vr = vendor_requests.demo()
    hist = risk_registers.history()
    sev_order = ("critical", "high", "moderate", "low")
    vulns = {s: {"open": 0, "overdue": 0} for s in sev_order}
    for i in items:
        vulns[i.severity]["open"] += 1
        vulns[i.severity]["overdue"] += i.sla_status == "overdue"
    done_vr = [r for r in vr if r["state"] in ("approved", "rejected")]
    closed_deals = [d for d in TRUST_PIPELINE if d["security_review"] == "done"]
    return {
        "as_of": today, "entity": ENTITY,
        "frameworks": fw,
        "business_units": bu,
        "controls": {"tested": len(by), "passing": sum(v["status"] == "pass" for v in by.values()),
                     "failing": sum(v["status"] == "fail" for v in by.values())},
        "failing_controls": sorted(c for c, v in by.items() if v["status"] == "fail"),
        "evidence": {k: ev[k] for k in ("counts", "records", "fresh_pct")},
        "poam": poam.summary(items),
        "risk": {"registers": risk_registers.by_register(), "trend": hist},
        "vendors": [{"id": v["vendor"], "name": v["name"], "tier": v["tier"], "score": v["score"], "band": v["band"]}
                    for v in vend],
        "vulnerabilities": vulns,
        "access_review": ar,
        "agents": {"mapper_precision": m["precision"], "mapper_recall": m["recall"],
                   "mapper_auto_rate": round(m["auto"] / m["items"], 3), "review_queue": m["review"],
                   "expert_review_board": rv["board"], "edited_after_compliant": len(rv["drift"]),
                   "ownership_escalations": ownership.ladder_counts(today)},
        "questionnaires": {"requests": len(vr), "completed": len(done_vr),
                           "avg_days_to_decision": round(sum(r["age"] for r in done_vr) / len(done_vr), 1)
                           if done_vr else None, "sla_breaches": sum(r["breached"] for r in vr)},
        "soc2": soc2_path.progress(by),
        "ai_policy": {k: v for k, v in ai_policy.status(today=today).items() if k != "parts"},
        "ai_governance": ai_governance.kpis(today),
        "ai_register": ai_governance.register_summary(today),
        "industry_packs": industry_packs.all_readiness(by),
        "scanner": {**scanner_import.kpis(today=today), "checks": scanner_import.checks(today=today)},
        "identity": resilience.identity_kpis(today),
        "trust_to_revenue": {"label": "SIMULATED", "deals": len(TRUST_PIPELINE),
                             "value_unblocked": sum(d["value"] for d in closed_deals),
                             "value_waiting": sum(d["value"] for d in TRUST_PIPELINE if d["security_review"] == "open"),
                             "avg_review_days": round(sum(d["days_in_review"] for d in TRUST_PIPELINE)
                                                      / len(TRUST_PIPELINE), 1)},
    }


def headline(m: dict) -> list[tuple[str, str, str]]:
    """(KPI, value, label) rows used in both reports."""
    c = m["controls"]
    return [
        ("Controls passing (tested)", f"{c['passing']} / {c['tested']}", "measured, synthetic"),
        ("Failing controls", str(c["failing"]), "measured, synthetic"),
        ("Evidence fresh", f"{m['evidence']['fresh_pct']}%", "measured, synthetic"),
        ("POA&M overdue", str(m["poam"]["by_sla"]["overdue"]), "measured, synthetic"),
        ("Critical + high open", str(m["vulnerabilities"]["critical"]["open"] + m["vulnerabilities"]["high"]["open"]),
         "measured, synthetic"),
        ("Access review complete", f"{m['access_review']['complete_pct']}%", "measured, synthetic"),
        ("SOC 2 path", m["soc2"]["label"], "measured, synthetic"),
        ("Value waiting on security review", f"${m['trust_to_revenue']['value_waiting']:,}", "SIMULATED"),
    ]


# ---------------------------------------------------------------------------------------------- render
def _table(head: list[str], rows: list[list]) -> str:
    th = "".join(f'<th style="text-align:left;border-bottom:1px solid #ccc;padding:3px 8px">{escape(h)}</th>'
                 for h in head)
    trs = "".join("<tr>" + "".join(f'<td style="padding:3px 8px">{escape(str(x))}</td>' for x in r) + "</tr>"
                  for r in rows)
    return f'<table style="border-collapse:collapse;font:12px Arial">{"<tr>" + th + "</tr>"}{trs}</table>'


def to_html(m: dict, kind: str = "weekly", top_frameworks: int | None = None) -> str:
    if kind not in KINDS:
        raise ValueError(kind)
    fw = m["frameworks"]
    if kind == "daily":
        fw = sorted(fw, key=lambda r: r["framework"] != "NIST_800_53")[: top_frameworks or 4]
    elif top_frameworks:
        fw = fw[:top_frameworks]
    h = ['<html><body style="font-family:Arial;max-width:720px">',
         f"<h2>{escape(m['entity'])}: {kind} security and compliance report</h2>",
         f'<p style="color:#a00">Synthetic data. As of {escape(m["as_of"])}. Not a real system. '
         f"Numbers are measured on the synthetic run unless marked SIMULATED.</p>",
         _table(["KPI", "Value", "Basis"], [list(r) for r in headline(m)]),
         "<h3>Framework readiness (ready controls / mapped controls)</h3>",
         "<p style='font-size:11px;color:#555'>Ready = tested and passing in the synthetic run. Untested counts as "
         "not ready. Mappings other than NIST 800-53 are approximate.</p>",
         svgchart.cards(fw)]
    h.append(svgchart.hbar([(r["name"], r["readiness_pct"]) for r in m["business_units"]], 100, "%",
                           title="Readiness by business unit (passing / tested)"))
    if kind == "weekly":
        v = m["vulnerabilities"]
        h.append(svgchart.stacked([(s, {"on time": d["open"] - d["overdue"], "overdue": d["overdue"]})
                                   for s, d in v.items()], [("on time", "info"), ("overdue", "bad")],
                                  title="Open findings by severity and SLA"))
        ec = m["evidence"]["counts"]
        h.append(svgchart.hbar([(k, n) for k, n in ec.items()], title="Evidence status"))
        trend = [t["total_residual"] for t in m["risk"]["trend"]]
        h.append(f"<h3>Risk posture</h3><p>Total residual risk, last {len(trend)} months: "
                 f"{trend[0]} to {trend[-1]} {svgchart.sparkline(trend, color='good')}</p>")
        h.append(_table(["Register", "Risks", "High", "Moderate", "Low"],
                        [[d["name"], d["risks"], d["high"], d["moderate"], d["low"]]
                         for d in m["risk"]["registers"].values()]))
        h.append("<h3>Vendor risk</h3>" + svgchart.hbar([(x["name"], x["score"]) for x in m["vendors"]], 100,
                                                       color="warn"))
        a = m["agents"]
        h.append("<h3>Agent KPIs (measured on labelled synthetic sets)</h3>" + _table(
            ["KPI", "Value"], [["Evidence mapper precision", a["mapper_precision"]],
                               ["Evidence mapper recall", a["mapper_recall"]],
                               ["Auto-accepted share", a["mapper_auto_rate"]],
                               ["Sent to human review", a["review_queue"]],
                               ["Controls edited after compliant (back in review)", a["edited_after_compliant"]],
                               ["Escalations owner / manager / CISO",
                                " / ".join(str(x) for x in a["ownership_escalations"].values())]]))
        q = m["questionnaires"]
        h.append("<h3>Vendor questionnaires</h3>" + _table(
            ["Requests", "Completed", "Avg days to decision", "SLA breaches"],
            [[q["requests"], q["completed"], q["avg_days_to_decision"], q["sla_breaches"]]]))
        t = m["trust_to_revenue"]
        h.append(f"<h3>Trust to revenue (SIMULATED)</h3><p>{t['deals']} simulated deals; "
                 f"${t['value_unblocked']:,} closed after review, ${t['value_waiting']:,} waiting; "
                 f"average review {t['avg_review_days']} days.</p>")
    ag = m["ai_governance"] if kind == "weekly" else [k for k in m["ai_governance"] if "daily" in k["report"]]
    h.append("<h3>AI Governance &amp; Accountability</h3>" + _table(["KPI", "Value", "Basis"],
                                                                 [[k["kpi"], k["value"], k["basis"]] for k in ag]))
    rg = m["ai_register"]
    if kind == "weekly":
        h.append(f"<p>Approved AI model and app register: {rg['entries']} entries {rg['by_status']}; "
                 f"{rg['uses_compliant']} of {rg['uses']} observed AI uses inside their approved scope; "
                 f"inventory coverage {rg['inventory_coverage_pct']}% (measured, synthetic).</p>")
    if kind == "weekly":
        h.append("<h3>Industry packs (approximate mappings)</h3>" + _table(
            ["Pack", "Framework", "Ready / mapped", "Ready %"],
            [[r["pack"], r["name"], f"{r['ready']} / {r['controls']}", f"{r['ready_pct']}%"]
             for r in m["industry_packs"]]))
    sc = m["scanner"]
    h.append("<h3>Vulnerability scanning evidence (RA-5, SI-2)</h3>" + _table(["Check", "Control", "Result", "Detail"], [
        [c["id"], c["control"], "PASS" if c["passed"] else "FAIL", c["detail"]] for c in sc["checks"]]) +
        f"<p>Open {sc['open']} {sc['by_severity']}; overdue {sc['overdue']}; known-exploited open {sc['kev_open']}; "
        f"scan coverage {sc['coverage_pct']}% (measured, synthetic).</p>")
    idk = m["identity"]
    h.append("<h3>Identity recovery</h3>" + _table(["KPI", "Value"], [
        ["Measured identity recovery time vs target",
         f"{idk['measured_rto_hours']}h vs {idk['target_rto_hours']}h ({'met' if idk['rto_met'] else 'MISSED'})"],
        ["Days since clean-room identity drill", idk["days_since_drill"]],
        ["Hours since last good identity backup", idk["backup_age_hours"]],
        ["Entra object types covered by backup", f"{idk['entra_object_coverage_pct']}%"],
        ["Identity resilience checks passing", f"{idk['checks_passed']} / {idk['checks']}"]]))
    h.append(f"<h3>Top failing controls</h3><p>{escape(', '.join(m['failing_controls'][:15]))}</p>")
    h.append('<p style="font-size:10px;color:#777">Generated offline by ARC-AMPE. Preview only: not sent.</p>'
             "</body></html>")
    return "\n".join(h)


def to_text(m: dict, kind: str = "weekly") -> str:
    lines = [f"{m['entity']}: {kind} report (synthetic data, as of {m['as_of']})", ""]
    lines += [f"- {k}: {v} [{b}]" for k, v, b in headline(m)]
    lines += ["", "Framework readiness:"]
    lines += [f"- {r['name']}: {r['ready']}/{r['controls']} ({r['ready_pct']}%)" for r in m["frameworks"]]
    return "\n".join(lines) + "\n"


def to_csv(m: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["section", "item", "metric", "value", "basis"])
    for k, v, b in headline(m):
        w.writerow(["headline", k, "value", v, b])
    for r in m["frameworks"]:
        w.writerow(["framework", r["name"], "ready", r["ready"], r["coverage"].split(" ")[0]])
        w.writerow(["framework", r["name"], "mapped", r["controls"], r["coverage"].split(" ")[0]])
        w.writerow(["framework", r["name"], "ready_pct", r["ready_pct"], r["coverage"].split(" ")[0]])
    for r in m["business_units"]:
        w.writerow(["business_unit", r["name"], "readiness_pct", r["readiness_pct"], "measured"])
    for s, d in m["vulnerabilities"].items():
        w.writerow(["findings", s, "open", d["open"], "measured"])
        w.writerow(["findings", s, "overdue", d["overdue"], "measured"])
    for s, n in m["evidence"]["counts"].items():
        w.writerow(["evidence", s, "count", n, "measured"])
    for v in m["vendors"]:
        w.writerow(["vendor", v["name"], "score", v["score"], "measured"])
    for t in m["risk"]["trend"]:
        w.writerow(["risk_trend", t["date"], "total_residual", t["total_residual"], "measured"])
    for k, v in m["agents"].items():
        if not isinstance(v, dict):
            w.writerow(["agents", k, "value", v, "measured"])
    for k in m["ai_governance"]:
        w.writerow(["ai_governance", k["kpi"], "value", k["value"], k["basis"]])
    for k in ("open", "overdue", "kev_open", "coverage_pct", "credentialed_pct", "never_scanned"):
        w.writerow(["scanner", k, "value", m["scanner"][k], "measured, synthetic"])
    for r in m["industry_packs"]:
        w.writerow(["industry_pack", f"{r['pack']}:{r['framework']}", "ready_pct", r["ready_pct"], "approximate"])
    for k, v in m["ai_register"].items():
        w.writerow(["ai_register", k, "value", v, "measured, synthetic"])
    for k, v in m["identity"].items():
        w.writerow(["identity_recovery", k, "value", v, "measured, synthetic"])
    w.writerow(["trust_to_revenue", "pipeline", "value_waiting", m["trust_to_revenue"]["value_waiting"], "SIMULATED"])
    return buf.getvalue()


def to_pdf(m: dict, kind: str = "weekly") -> bytes:
    d = minipdf.Doc()
    d.text(f"{m['entity']}: {kind} security and compliance report", 14, True)
    d.text(f"Synthetic data. As of {m['as_of']}. Not a real system.", 9)
    d.gap()
    for k, v, b in headline(m):
        d.text(f"{k}: {v}  [{b}]", 10)
    d.gap()
    d.text("Framework readiness (ready / mapped)", 12, True)
    for r in m["frameworks"]:
        rgb = (0.18, 0.49, 0.2) if r["ready_pct"] >= 80 else (0.98, 0.66, 0.15) if r["ready_pct"] >= 50 \
            else (0.78, 0.16, 0.16)
        d.bar(r["name"], r["ready_pct"], 100, f"{r['ready']}/{r['controls']}", rgb)
    d.gap()
    d.text("Readiness by business unit", 12, True)
    for r in m["business_units"]:
        d.bar(r["name"], r["readiness_pct"], 100, f"{r['readiness_pct']}%")
    d.gap()
    d.text("AI Governance & Accountability", 12, True)
    for k in m["ai_governance"]:
        if kind == "weekly" or "daily" in k["report"]:
            d.text(f"{k['kpi']}: {k['value']} [{k['basis']}]", 9)
    d.gap()
    idk = m["identity"]
    d.text("Identity recovery", 12, True)
    d.text(f"Measured recovery {idk['measured_rto_hours']}h vs target {idk['target_rto_hours']}h; "
           f"{idk['days_since_drill']} days since drill; backup age {idk['backup_age_hours']}h", 9)
    if kind == "weekly":
        d.gap()
        d.text("Open findings by severity", 12, True)
        mx = max(x["open"] for x in m["vulnerabilities"].values()) or 1
        for s, x in m["vulnerabilities"].items():
            d.bar(s, x["open"], mx, f"{x['open']} ({x['overdue']} overdue)")
        d.gap()
        d.text("Vendor risk score", 12, True)
        for v in m["vendors"]:
            d.bar(v["name"], v["score"], 100, str(v["score"]))
    return d.to_bytes()


def to_eml(m: dict, kind: str = "weekly", to=DEFAULT_TO) -> bytes:
    import datetime as dt
    msg = EmailMessage()
    msg["From"] = FROM
    msg["To"] = ", ".join(to)
    msg["Subject"] = f"[PREVIEW - NOT SENT] {m['entity']} {kind} security report {m['as_of']}"
    msg["Date"] = format_datetime(dt.datetime.fromisoformat(m["as_of"] + "T07:00:00-04:00"))
    msg["Message-ID"] = f"<{kind}-{m['as_of']}@reports.lakehaven-hx.example>"
    msg["X-ARCAMPE-Preview"] = "true"
    msg.set_content(to_text(m, kind))
    msg.add_alternative(to_html(m, kind), subtype="html")
    msg.add_attachment(to_pdf(m, kind), maintype="application", subtype="pdf", filename=f"{kind}-report.pdf")
    msg.add_attachment(to_csv(m).encode(), maintype="text", subtype="csv", filename=f"{kind}-report.csv")
    for i, part in enumerate(p for p in msg.walk() if p.is_multipart()):  # fixed boundaries: same input, same bytes
        part.set_boundary(f"==arcampe-{kind}-{i}==")
    return bytes(msg)


def write_previews(out_dir, kind: str = "weekly", m: dict | None = None) -> list[str]:
    import pathlib
    m = m or metrics()
    d = pathlib.Path(out_dir) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    files = {f"{kind}.html": to_html(m, kind).encode(), f"{kind}.eml": to_eml(m, kind),
             f"{kind}.pdf": to_pdf(m, kind), f"{kind}.csv": to_csv(m).encode()}
    for name, data in files.items():
        (d / name).write_bytes(data)
    return sorted(str(d / n) for n in files)


# ---------------------------------------------------------------------------------------------- sending
def check_send_config(config: dict | None) -> list[str]:
    errs = []
    if not config:
        return ["no send config: previews only"]
    if config.get("enabled") is not True:
        errs.append("config.enabled is not true")
    if config.get("transport") not in ("smtp", "sendgrid", "logic_apps"):
        errs.append("config.transport must be smtp, sendgrid or logic_apps")
    to = config.get("to") or []
    if not to:
        errs.append("config.to is empty")
    allowed = config.get("allowed_domains") or []
    for addr in to:
        if not allowed or addr.split("@")[-1] not in allowed:
            errs.append(f"recipient {addr} is not in allowed_domains")
    if any(k in config for k in ("api_key", "password", "token")):
        errs.append("secrets must not be in the config file; use a vault reference")
    return errs


def send(eml: bytes, config: dict | None = None, approved: bool = False, transport=None) -> dict:
    """Refuses unless config is valid, approved is True, and a transport callable is supplied."""
    errs = check_send_config(config)
    if not approved:
        errs.append("approval flag not set")
    if transport is None:
        errs.append("no transport supplied (this repo ships none)")
    if errs:
        raise SendRefused("; ".join(errs))
    receipt = transport(eml, list(config["to"]))
    return {"sent": True, "transport": config["transport"], "to": list(config["to"]), "receipt": receipt}


# ---------------------------------------------------------------------------------------------- schedule
SCHEDULE = {
    "timezone": "America/New_York",
    "daily": {"cron": "0 7 * * 1-5", "kind": "daily", "to": ["ciso@lakehaven-hx.example"]},
    "weekly": {"cron": "0 7 * * 1", "kind": "weekly", "to": ["leadership@lakehaven-hx.example"]},
}


def crontab(python: str = "python", repo: str = "/opt/arc-ampe") -> str:
    return "\n".join([
        "# ARC-AMPE leadership reports (previews only unless sending is configured and approved)",
        "CRON_TZ=America/New_York",
        f"{SCHEDULE['daily']['cron']} cd {repo} && {python} -m arcampe.grc report --kind daily --out out",
        f"{SCHEDULE['weekly']['cron']} cd {repo} && {python} -m arcampe.grc report --kind weekly --out out",
    ]) + "\n"


def schedule_json() -> str:
    return json.dumps(SCHEDULE, indent=1, sort_keys=True) + "\n"
