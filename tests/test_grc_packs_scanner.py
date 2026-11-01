import pytest

from arcampe import catalog
from arcampe.grc import industry_packs as ip
from arcampe.grc import scanner_import as s
from arcampe.integrations import schema


# ---------------------------------------------------------------- industry packs
def test_pack_names():
    assert set(ip.PACKS) == {"health_exchange", "banking_credit_union", "defense", "legal", "broker_dealer_adviser"}


@pytest.mark.parametrize("fw", ["FFIEC_ACET", "ABA_1_6", "SEC_REG_SP", "CMMC_L2"])
def test_requested_frameworks_present(fw):
    assert any(fw in v for v in ip.PACKS.values())


@pytest.mark.parametrize("pack", sorted(ip.PACKS))
def test_pack_readiness_rows(pack):
    rows = ip.readiness(pack)
    assert len(rows) == len(ip.PACKS[pack])
    for r in rows:
        assert r["ready"] + r["failing"] + r["untested"] == r["controls"] and r["coverage"] == "approximate"


@pytest.mark.parametrize("fw,ready,controls", [("FFIEC_ACET", 113, 392), ("SEC_REG_SP", 71, 282),
                                                ("ABA_1_6", 52, 254), ("CMMC_L2", 68, 295)])
def test_pack_measured(fw, ready, controls):
    r = next(x for x in ip.all_readiness() if x["framework"] == fw)
    assert (r["ready"], r["controls"]) == (ready, controls)


@pytest.mark.parametrize("fw", sorted(ip.PACK_MAP))
def test_pack_map_families_valid(fw):
    fams = {c.family for c in catalog.baseline("ae")}
    assert set(ip.PACK_MAP[fw]) <= fams


def test_aba_has_no_physical_mapping():
    assert "PE" not in ip.PACK_MAP["ABA_1_6"]


def test_reg_sp_covers_incident_and_vendor():
    m = ip.PACK_MAP["SEC_REG_SP"]
    assert "248.30(a)(4)" in m["IR"] and m["SR"] == ("248.30(a)(5)",)


def test_ffiec_five_domains():
    doms = {v.split(".")[0] for vals in ip.PACK_MAP["FFIEC_ACET"].values() for v in vals}
    assert doms == {"D1", "D2", "D3", "D4", "D5"}


def test_unknown_pack():
    with pytest.raises(KeyError):
        ip.readiness("nope")


# ---------------------------------------------------------------- multi-org isolation
@pytest.fixture
def mo():
    return ip.demo()


@pytest.mark.parametrize("org", [o.id for o in ip.ORGS])
def test_own_org_access(mo, org):
    assert len(mo.status(f"k-{org}", org)) >= 200


@pytest.mark.parametrize("key,org", [("k-cedarbrook", "ironvale"), ("k-ironvale", "lakehaven"),
                                     ("k-marlow", "cedarbrook"), ("k-unknown", "marlow"), ("k-lakehaven", "northgate")])
def test_cross_org_refused(mo, key, org):
    with pytest.raises(ip.TenantIsolationError):
        mo.status(key, org)
    assert mo.log.entries()[-1].action == "tenant.refused"


def test_evidence_isolated(mo):
    mo.add_evidence("k-cedarbrook", "cedarbrook", {"kind": "policy_doc"})
    assert mo.evidence("k-ironvale", "ironvale") == []
    assert mo.evidence("k-cedarbrook", "cedarbrook")[0]["tenant"] == "cedarbrook"


def test_evidence_wrong_tenant_label_refused(mo):
    with pytest.raises(ip.TenantIsolationError):
        mo.add_evidence("k-cedarbrook", "cedarbrook", {"tenant": "ironvale"})


def test_evidence_list_is_a_copy(mo):
    mo.add_evidence("k-marlow", "marlow", {"kind": "x"})
    mo.evidence("k-marlow", "marlow").clear()
    assert len(mo.evidence("k-marlow", "marlow")) == 1


def test_audit_log_verifies(mo):
    mo.status("k-marlow", "marlow")
    with pytest.raises(ip.TenantIsolationError):
        mo.status("k-marlow", "ironvale")
    assert mo.log.verify()[0]


def test_orgs_differ_but_deterministic():
    a, b = ip._synthetic_status("cedarbrook"), ip._synthetic_status("ironvale")
    assert a != b and a == ip._synthetic_status("cedarbrook")


def test_portfolio_counts_only(mo):
    p = mo.portfolio()
    assert len(p) == 5 and all(set(r) == {"org", "name", "pack", "tested", "passing", "readiness_pct"} for r in p)
    assert p[0]["readiness_pct"] == 57.5


def test_org_pack_readiness(mo):
    rows = mo.pack_readiness("k-ironvale", "ironvale")
    assert [r["framework"] for r in rows] == ["CMMC_L2", "NIST_800_171"]


def test_org_domains_fictional():
    assert all(o.domain.endswith(".example") for o in ip.ORGS)


# ---------------------------------------------------------------- scanner import
@pytest.fixture(scope="module")
def rows():
    return s.load()


def test_rows(rows):
    assert len(rows) == 11 and {r["host"] for r in rows} >= {"vm-lhx-web-01", "vm-lhx-db-01"}


def test_xml_matches_csv_for_same_hosts(rows):
    x = s.load(s.SCAN_DIR / "scan_web_2026-10.xml")
    hosts = {r["host"] for r in x}
    key = lambda r: (r["host"], r["plugin"])  # noqa: E731
    assert sorted(map(key, x)) == sorted(key(r) for r in rows if r["host"] in hosts)


def test_xml_doctype_refused():
    with pytest.raises(s.ScanImportError):
        s.parse_xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><ScanReport/>')


def test_csv_missing_columns():
    with pytest.raises(s.ScanImportError):
        s.parse_csv("Host,Risk\nh,High\n")


def test_unknown_risk():
    with pytest.raises(s.ScanImportError):
        s.parse_csv("Plugin ID,Risk,Host,Scan Start\n1,Severe,h,2026-10-01\n")


@pytest.mark.parametrize("risk,sev", [("Critical", "critical"), ("High", "high"), ("Medium", "moderate"),
                                      ("Low", "low")])
def test_risk_mapping(risk, sev):
    r = s.parse_csv(f"Plugin ID,Risk,Host,Scan Start\n1,{risk},h,2026-10-01\n")
    assert r[0]["severity"] == sev


def test_injection_quarantined(rows):
    q = [r for r in rows if r["quarantined"]]
    assert len(q) == 1 and "Ignore previous" not in q[0]["solution"]


def test_evidence_kinds(rows):
    ev = s.to_evidence(rows)
    assert sum(e.kind == "vuln_scan" for e in ev) == 6 and sum(e.kind == "flaw_remediation" for e in ev) == 11
    assert all(schema.verify(e) for e in ev)


def test_credentialed_hint(rows):
    ev = {e.subject: e for e in s.to_evidence(rows) if e.kind == "vuln_scan"}
    assert "RA-05(05)" in ev["vm-lhx-web-01"].control_hints
    assert "RA-05(05)" not in ev["vm-lhx-batch-01"].control_hints


def test_coverage(rows):
    c = s.coverage(rows)
    assert (c["coverage_pct"], c["never_scanned"], c["stale"]) == (71.4, ["vm-lhx-reporting-01"], ["vm-lhx-jump-01"])


def test_kpis(rows):
    k = s.kpis(rows)
    assert k["by_severity"] == {"critical": 1, "high": 5, "moderate": 3, "low": 2}
    assert (k["overdue"], k["kev_open"]) == (8, 4)


@pytest.mark.parametrize("cid,passed", [("SCAN-COVERAGE", False), ("SCAN-CREDENTIALED", False), ("SCAN-SLA", False),
                                        ("SCAN-KEV", False), ("SCAN-SCREEN", True)])
def test_checks(rows, cid, passed):
    assert {c["id"]: c["passed"] for c in s.checks(rows)}[cid] is passed


def test_open_items_sorted_overdue_first(rows):
    items = s.open_items(rows)
    st = [i["sla_status"] for i in items]
    assert st == sorted(st, key=lambda x: x != "overdue")


def test_sla_due_uses_params(rows):
    i = next(x for x in s.open_items(rows) if x["plugin"] == "990001")
    assert i["due"] == "2026-10-25" and i["sla_status"] == "overdue"


def test_all_fixed_passes_sla():
    r = s.parse_csv("Plugin ID,Risk,Host,Scan Start,First Found\n1,Low,h,2026-10-30,2026-10-30\n")
    assert {c["id"]: c["passed"] for c in s.checks(r)}["SCAN-SLA"]


def test_fictional_cves(rows):
    assert all(r["cve"] is None or r["cve"].startswith("CVE-2099-") for r in rows)


def test_report_has_scanner_and_packs():
    from arcampe.grc import reporting
    m = reporting.metrics()
    w = reporting.to_html(m, "weekly")
    assert "RA-5, SI-2" in w and "Industry packs" in w
    assert "Industry packs" not in reporting.to_html(m, "daily")
    assert "scanner,kev_open" in reporting.to_csv(m)
