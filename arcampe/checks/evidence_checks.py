"""Checks that decide pass/fail from normalized connector evidence (not from cloud configs)."""
from __future__ import annotations

import datetime as dt

from .. import TODAY
from ..params import PARAMS
from .base import Check, Finding


def _days(a: str, b: str = TODAY) -> int:
    return (dt.date.fromisoformat(b[:10]) - dt.date.fromisoformat(a[:10])).days


def _of(ev, kind=None, source=None):
    return [e for e in ev if (kind is None or e.kind == kind) and (source is None or e.source == source)]


def offboarding_same_day(ev):
    """PS-04: every termination has its account disabled in every IdP on the same day."""
    out = []
    accounts: dict[str, list] = {}
    for a in _of(ev, "account"):
        accounts.setdefault(a.subject, []).append(a)
    for h in _of(ev, "hr_event"):
        if h.attributes["event"] != "termination":
            continue
        accts = accounts.get(h.subject, [])
        late = [a.source for a in accts if a.attributes["enabled"] or not a.attributes.get("disabled_on")
                or _days(h.observed_at, a.attributes["disabled_on"]) > 0]
        ok = bool(accts) and not late
        detail = "no IdP account found" if not accts else ("disabled same day in all IdPs" if ok else
                                                           f"not disabled same day in: {sorted(late)}")
        out.append((h.subject, ok, detail))
    return out


def changes_approved(ev):
    """CM-03 / CM-03(02): prod changes are approved, tested and tied to a reviewed pull request."""
    reviews = {p.subject: p.attributes["approved_reviews"] for p in _of(ev, "pull_request")}
    out = []
    for c in _of(ev, "change"):
        a = c.attributes
        problems = [m for m, bad in [("not approved", not a["approved"]), ("no test evidence", not a["tested"]),
                                     ("no linked PR", not a["pr"]),
                                     ("PR not reviewed", a["pr"] and reviews.get(a["pr"], 0) < 1)] if bad]
        out.append((c.subject, not problems, "approved, tested, reviewed" if not problems else ", ".join(problems)))
    return out


def audit_review_weekly(ev):
    """AU-06: the latest audit log review is no older than the ARC-AMPE weekly cadence."""
    limit = PARAMS["AU-06"]["review_every_days"]
    revs = _of(ev, "log_review")
    if not revs:
        return [("audit-review", False, "no review records")]
    newest = min(_days(r.observed_at) for r in revs)
    return [("audit-review", newest <= limit, f"last review {newest} day(s) ago (max {limit})")]


def siem_integration(ev):
    """AU-06(01): identity, cloud, endpoint/security and SaaS sources all feed the SIEM."""
    need = {"EntraID", "AzureActivity", "DefenderForCloud", "Office365"}
    got = set()
    for s in _of(ev, "siem_sources"):
        got.update(s.attributes["sources"])
    missing = sorted(need - got)
    return [("siem", not missing, "all required sources connected" if not missing else f"missing: {missing}")]


def code_scanning(ev):
    """SA-11: every repository runs code scanning and secret scanning."""
    return [(r.subject, r.attributes["code_scanning"] and r.attributes["secret_scanning"],
             f"code scanning={r.attributes['code_scanning']} secret scanning={r.attributes['secret_scanning']}")
            for r in _of(ev, "repo_setting")]


def incident_reported_1h(ev):
    """IR-06: PII incidents reported to CMS within one hour of discovery (AE requirement)."""
    limit = PARAMS["IR-06"]["report_within_hours"] * 60
    out = []
    for i in _of(ev, "incident"):
        a = i.attributes
        if not a["pii"]:
            continue
        if not a["reported_to_cms"]:
            out.append((i.subject, False, "not reported"))
            continue
        mins = int((dt.datetime.fromisoformat(a["reported_to_cms"])
                    - dt.datetime.fromisoformat(a["detected"])).total_seconds() // 60)
        out.append((i.subject, mins <= limit, f"reported after {mins} min (max {limit})"))
    return out


def scanner_feed_fresh(ev):
    """RA-05(02): vulnerability feeds were updated within the 30-day scan cycle."""
    limit = PARAMS["RA-05"]["scan_every_days"]
    return [(s.subject, _days(s.attributes["feed_updated"]) <= limit,
             f"feed updated {_days(s.attributes['feed_updated'])} day(s) ago")
            for s in _of(ev, "vuln_scan")]


def dlp_on_boundary(ev):
    """SC-07(24): a DLP policy blocks PII leaving through mail and file sharing."""
    enforced = [d for d in _of(ev, "dlp_policy") if d.attributes["enforced"]
                and {"Exchange", "SharePoint"} <= set(d.attributes["locations"])]
    return [("dlp", bool(enforced), f"{len(enforced)} enforced PII DLP policy(ies) on mail and files")]


def no_anonymous_pii_sharing(ev):
    """AC-22: PII sites never allow external or guest sharing."""
    return [(s.subject, not (s.attributes["sensitivity"] == "PII" and s.attributes["sharing"] != "Disabled"),
             f"sharing={s.attributes['sharing']} sensitivity={s.attributes['sensitivity']}")
            for s in _of(ev, "share_setting")]


def firewall_default_deny(ev):
    """SC-07(05): no any-to-any allow rules; traffic is denied unless allowed."""
    rules = _of(ev, "firewall_rule")
    bad = [r.subject for r in rules if r.attributes["any_any_allow"]]
    return [("firewall", not bad, "default deny, no any-any allow" if not bad else f"any-any allow: {bad}")]


def alerts_routed(ev):
    """SI-04(05): every security monitor alerts a person (not muted, has a recipient)."""
    return [(m.subject, m.attributes["routed"], "routed" if m.attributes["routed"] else "muted or no recipient")
            for m in _of(ev, "monitor")]


def restore_tested(ev):
    """CP-09(01): each backed-up system had a restore test in the last year."""
    seen: dict[str, str | None] = {}
    for j in _of(ev, "backup_job"):
        t = j.attributes["restore_tested_on"]
        seen[j.subject] = max(filter(None, [seen.get(j.subject), t]), default=None)
    return [(k, v is not None and _days(v) <= 365, f"last restore test {('never' if v is None else str(_days(v)) + ' days ago')}")
            for k, v in sorted(seen.items())]


def vendor_breach_clause(ev):
    """SR-08: vendors with PII access must notify of a breach within one hour by contract."""
    limit = PARAMS["IR-06"]["report_within_hours"]
    return [(v.subject, (h := v.attributes.get("contract_breachNotifyHours")) is not None and h <= limit,
             f"{v.attributes['name']}: breach notice {h}h")
            for v in _of(ev, "vendor") if v.attributes["pii"]]


EV = "evidence"
CHECKS: tuple[Check, ...] = (
    Check("EV-01", "Leavers disabled the same day in every identity provider", ("PS-04",), "high", (EV,),
          offboarding_same_day),
    Check("EV-02", "Production changes approved, tested and peer reviewed", ("CM-03", "CM-03(02)"), "moderate",
          (EV,), changes_approved),
    Check("EV-03", "Audit logs reviewed at least weekly", ("AU-06",), "moderate", (EV,), audit_review_weekly),
    Check("EV-04", "SIEM receives all required sources", ("AU-06(01)", "AU-06(03)"), "moderate", (EV,),
          siem_integration),
    Check("EV-05", "Code and secret scanning on every repo", ("SA-11",), "moderate", (EV,), code_scanning),
    Check("EV-06", "PII incidents reported to CMS within 1 hour", ("IR-06",), "high", (EV,), incident_reported_1h),
    Check("EV-07", "Vulnerability feeds current", ("RA-05(02)",), "moderate", (EV,), scanner_feed_fresh),
    Check("EV-08", "DLP enforces PII rules at the boundary", ("SC-07(24)",), "high", (EV,), dlp_on_boundary),
    Check("EV-09", "No external sharing of PII sites", ("AC-22",), "high", (EV,), no_anonymous_pii_sharing),
    Check("EV-10", "Firewall denies by default", ("SC-07(05)",), "high", (EV,), firewall_default_deny),
    Check("EV-11", "Security monitors route alerts to people", ("SI-04(05)",), "moderate", (EV,), alerts_routed),
    Check("EV-12", "Backups restore-tested in the last year", ("CP-09(01)",), "moderate", (EV,), restore_tested),
    Check("EV-13", "PII vendors must report breaches within 1 hour", ("SR-08",), "moderate", (EV,),
          vendor_breach_clause),
)


def all_checks() -> tuple[Check, ...]:
    return CHECKS


def run(evidence=None, checks=CHECKS) -> list[Finding]:
    if evidence is None:
        from ..integrations.connectors import collect_all
        evidence = collect_all()
    out = []
    for chk in checks:
        for subject, ok, detail in chk.fn(evidence):
            out.append(Finding(chk.id, f"evidence/{subject}", subject, ok, chk.severity, chk.controls, detail))
    return out
