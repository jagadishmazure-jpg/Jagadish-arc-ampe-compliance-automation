"""Scanner evidence import for RA-5 (vulnerability monitoring and scanning) and SI-2 (flaw remediation).

Reads a synthetic Nessus-style CSV or XML export (data/grc/scanner/), screens free-text fields for injection text,
and produces:

* one `vuln_scan` evidence record per host (RA-05; credentialed scans also RA-05(05)), with scan date so the
  evidence-status module can mark stale scans "Needs Renewal";
* one `flaw_remediation` record per open vulnerability (SI-02) with its SLA due date from params.SLA_DAYS;
* POA&M-style rows for every open finding;
* coverage against a small synthetic host inventory (one host was never scanned).
Plugin IDs and CVE-2099-* IDs are fictional. XML with a DOCTYPE or entity declaration is refused.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import xml.etree.ElementTree as ET  # noqa: S405 - DOCTYPE/ENTITY refused before parsing

from .. import DATA, TODAY, guards
from ..integrations import schema
from ..params import SLA_DAYS

SCAN_DIR = DATA / "grc" / "scanner"
RISK = {"critical": "critical", "high": "high", "medium": "moderate", "moderate": "moderate", "low": "low"}
INVENTORY = ("vm-lhx-web-01", "vm-lhx-web-02", "vm-lhx-api-01", "vm-lhx-batch-01", "vm-lhx-jump-01", "vm-lhx-db-01",
             "vm-lhx-reporting-01")
SCAN_WINDOW_DAYS = 30


class ScanImportError(ValueError):
    pass


def _row(plugin, cve, cvss, risk, host, ip, port, name, solution, first, scan, cred, kev) -> dict:
    sev = RISK.get(str(risk).strip().lower())
    if sev is None:
        raise ScanImportError(f"unknown risk {risk!r}")
    flags = guards.screen(f"{name} {solution}")
    return {"plugin": str(plugin), "cve": cve or None, "cvss": float(cvss), "severity": sev, "host": host, "ip": ip,
            "port": int(port), "name": name, "solution": "[quarantined: suspicious text]" if flags else solution,
            "quarantined": bool(flags), "first_found": first, "scan_start": scan,
            "credentialed": str(cred).lower() == "yes", "kev": str(kev).lower() == "yes"}


def parse_csv(text: str) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(text)))
    need = {"Plugin ID", "Risk", "Host", "Scan Start"}
    if rows and not need <= set(rows[0]):
        raise ScanImportError(f"missing columns: {sorted(need - set(rows[0]))}")
    return [_row(r["Plugin ID"], r.get("CVE"), r.get("CVSS v3.0 Base Score") or 0, r["Risk"], r["Host"], r.get("IP", ""),
                 r.get("Port") or 0, r.get("Name", ""), r.get("Solution", ""), r.get("First Found") or r["Scan Start"],
                 r["Scan Start"], r.get("Credentialed", "no"), r.get("Known Exploited", "no")) for r in rows]


def parse_xml(text: str) -> list[dict]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ScanImportError("DOCTYPE or ENTITY declarations are not accepted")
    root = ET.fromstring(text)  # noqa: S314 - DTDs refused above
    out = []
    for h in root.iter("ReportHost"):
        for it in h.iter("ReportItem"):
            out.append(_row(it.get("pluginID"), it.get("cve"), it.get("cvss3") or 0, it.get("risk"), h.get("name"),
                            h.get("ip", ""), it.get("port") or 0, it.findtext("name", ""), it.findtext("solution", ""),
                            it.get("first_found") or h.get("scan_start"), h.get("scan_start"),
                            h.get("credentialed", "no"), it.get("kev", "no")))
    return out


def load(path=None) -> list[dict]:
    if path is not None:
        t = path.read_text()
        return parse_xml(t) if path.suffix == ".xml" else parse_csv(t)
    return parse_csv((SCAN_DIR / "scan_2026-10.csv").read_text())


def hosts(rows: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in rows:
        h = out.setdefault(r["host"], {"host": r["host"], "scan_start": r["scan_start"],
                                       "credentialed": r["credentialed"], "findings": 0})
        h["findings"] += 1
        h["scan_start"] = max(h["scan_start"], r["scan_start"])
    return out


def open_items(rows: list[dict], today: str = TODAY) -> list[dict]:
    t = dt.date.fromisoformat(today)
    out = []
    for r in rows:
        due = dt.date.fromisoformat(r["first_found"]) + dt.timedelta(days=SLA_DAYS[r["severity"]])
        left = (due - t).days
        out.append({"id": f"SCAN-{r['plugin']}:{r['host']}", "host": r["host"], "plugin": r["plugin"],
                    "cve": r["cve"], "severity": r["severity"], "kev": r["kev"], "first_found": r["first_found"],
                    "due": due.isoformat(), "days_open": (t - dt.date.fromisoformat(r["first_found"])).days,
                    "sla_status": "overdue" if left < 0 else "due_soon" if left <= 7 else "on_track",
                    "controls": ("SI-02", "RA-05"), "quarantined": r["quarantined"]})
    return sorted(out, key=lambda x: (x["sla_status"] != "overdue", -x["kev"], x["due"], x["id"]))


def to_evidence(rows: list[dict], tenant: str = "lakehaven") -> list:
    ev = []
    for h in hosts(rows).values():
        hints = ("RA-05", "RA-05(05)") if h["credentialed"] else ("RA-05",)
        ev.append(schema.make(tenant, "scanner-import", "security", "vuln_scan", h["host"], h["scan_start"],
                              {"credentialed": h["credentialed"], "findings": h["findings"]}, hints))
    for i in open_items(rows):
        ev.append(schema.make(tenant, "scanner-import", "security", "flaw_remediation", i["id"], i["first_found"],
                              {k: i[k] for k in ("severity", "cve", "due", "sla_status", "kev")}, ("SI-02",)))
    return ev


def coverage(rows: list[dict], today: str = TODAY, window: int = SCAN_WINDOW_DAYS) -> dict:
    t = dt.date.fromisoformat(today)
    hs = hosts(rows)
    fresh = [h for h in hs.values() if (t - dt.date.fromisoformat(h["scan_start"])).days <= window]
    return {"inventory": len(INVENTORY), "scanned": len(hs), "scanned_in_window": len(fresh),
            "coverage_pct": round(100 * len(fresh) / len(INVENTORY), 1),
            "credentialed_pct": round(100 * sum(h["credentialed"] for h in hs.values()) / len(hs), 1) if hs else 0.0,
            "never_scanned": sorted(set(INVENTORY) - set(hs)),
            "stale": sorted(h["host"] for h in hs.values() if h not in fresh)}


def checks(rows: list[dict] | None = None, today: str = TODAY) -> list[dict]:
    rows = load() if rows is None else rows
    cov = coverage(rows, today)
    items = open_items(rows, today)
    overdue = [i for i in items if i["sla_status"] == "overdue"]
    kev_over = [i for i in overdue if i["kev"]]
    return [
        {"id": "SCAN-COVERAGE", "control": "RA-05", "passed": cov["coverage_pct"] >= 95,
         "detail": f"{cov['scanned_in_window']}/{cov['inventory']} hosts scanned in {SCAN_WINDOW_DAYS} days; "
                   f"never scanned {cov['never_scanned']}; stale {cov['stale']}"},
        {"id": "SCAN-CREDENTIALED", "control": "RA-05(05)", "passed": cov["credentialed_pct"] >= 90,
         "detail": f"{cov['credentialed_pct']}% of scanned hosts used credentials"},
        {"id": "SCAN-SLA", "control": "SI-02", "passed": not overdue,
         "detail": f"{len(overdue)} of {len(items)} open findings past SLA"},
        {"id": "SCAN-KEV", "control": "SI-02", "passed": not kev_over,
         "detail": f"{len(kev_over)} known-exploited findings past SLA"},
        {"id": "SCAN-SCREEN", "control": "SI-10",
         "passed": all(r["solution"].startswith("[quarantined") for r in rows if r["quarantined"]),
         "detail": f"{sum(r['quarantined'] for r in rows)} rows had injection-like text and were quarantined"},
    ]


def kpis(rows: list[dict] | None = None, today: str = TODAY) -> dict:
    rows = load() if rows is None else rows
    items = open_items(rows, today)
    cov = coverage(rows, today)
    by = {s: sum(i["severity"] == s for i in items) for s in ("critical", "high", "moderate", "low")}
    return {"open": len(items), "by_severity": by, "overdue": sum(i["sla_status"] == "overdue" for i in items),
            "kev_open": sum(i["kev"] for i in items), "coverage_pct": cov["coverage_pct"],
            "credentialed_pct": cov["credentialed_pct"], "never_scanned": len(cov["never_scanned"])}
