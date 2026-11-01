"""Extended framework crosswalks and the full framework registry.

The core crosswalk (arcampe/crosswalk.py) covers HIPAA, SOC 2, ISO 27001, PCI DSS, GDPR, CCPA, COBIT and a
FedRAMP proxy. This module adds 24 more frameworks at NIST 800-53 family level. Every one of them is
**approximate**: written by the author from public structure (section, article, domain or category IDs only, no
framework text), not an official mapping from the framework owner. A family that has no sensible match maps to
nothing and shows up as a gap.

The registry lists 34 frameworks. It is checked against the public framework list of one commercial GRC product
(see docs/SOURCE_COVERAGE.md; no affiliation). "Public size" is the structure of the public standard itself,
never a vendor number.
"""
from __future__ import annotations

from functools import lru_cache

from .. import catalog, crosswalk

FAM = ("AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC",
       "SI", "SR")


def _m(**kw) -> dict[str, tuple[str, ...]]:
    return {k: tuple(v) if isinstance(v, (list, tuple)) else (v,) for k, v in kw.items()}


EXT_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "NIST_800_171": _m(  # Rev 3 requirement families 03.01-03.17
        AC="03.01", AT="03.02", AU="03.03", CM="03.04", IA="03.05", IR="03.06", MA="03.07", MP="03.08",
        PS="03.09", PE="03.10", RA="03.11", CA="03.12", SC="03.13", SI="03.14", PL="03.15", SA="03.16", SR="03.17"),
    "CMMC_L2": _m(  # CMMC 2.0 Level 2 domains (built on 800-171 Rev 2)
        AC="AC.L2", AT="AT.L2", AU="AU.L2", CM="CM.L2", IA="IA.L2", IR="IR.L2", MA="MA.L2", MP="MP.L2",
        PS="PS.L2", PE="PE.L2", RA="RA.L2", CA="CA.L2", SC="SC.L2", SI="SI.L2"),
    "NIST_CSF_2": _m(  # CSF 2.0 category IDs
        AC="PR.AA", AT="PR.AT", AU=("DE.CM", "PR.PS"), CA=("ID.IM", "GV.OV"), CM="PR.PS", CP=("RC.RP", "PR.IR"),
        IA="PR.AA", IR=("RS.MA", "RS.AN", "RS.CO", "RS.MI"), MA="PR.PS", MP="PR.DS", PE=("PR.AA", "PR.IR"),
        PL="GV.PO", PM=("GV.RM", "GV.RR", "GV.OC"), PS="GV.RR", PT=("GV.OC", "PR.DS"), RA="ID.RA",
        SA=("GV.SC", "PR.PS"), SC=("PR.DS", "PR.IR"), SI=("DE.CM", "DE.AE"), SR="GV.SC"),
    "NIS2": _m(  # Directive (EU) 2022/2555, Art. 21(2) points, Art. 20 governance, Art. 23 reporting
        AC="Art.21(2)(i)", AT="Art.21(2)(g)", AU="Art.21(2)(b)", CA="Art.21(2)(f)", CM=("Art.21(2)(e)", "Art.21(2)(i)"),
        CP="Art.21(2)(c)", IA=("Art.21(2)(j)", "Art.21(2)(i)"), IR=("Art.21(2)(b)", "Art.23"), MA="Art.21(2)(e)",
        MP="Art.21(2)(i)", PL="Art.21(2)(a)", PM=("Art.20", "Art.21(2)(a)"), PS="Art.21(2)(i)", RA="Art.21(2)(a)",
        SA=("Art.21(2)(d)", "Art.21(2)(e)"), SC=("Art.21(2)(h)", "Art.21(2)(j)"), SI="Art.21(2)(e)",
        SR="Art.21(2)(d)"),
    "HITRUST": _m(  # HITRUST CSF control category numbers 00-13 (category level only)
        AC="01", AT="02", AU="09", CA="06", CM=("09", "10"), CP="12", IA="01", IR="11", MA="09", MP="09", PE="08",
        PL="04", PM=("00", "05"), PS="02", PT="13", RA="03", SA="10", SC="09", SI=("09", "10"), SR="05"),
    "DORA": _m(  # Regulation (EU) 2022/2554 articles
        AC="Art.9", AT="Art.13", AU="Art.10", CA=("Art.24", "Art.25"), CM=("Art.8", "Art.9"), CP=("Art.11", "Art.12"),
        IA="Art.9", IR=("Art.17", "Art.19"), MA="Art.7", MP="Art.9", PE="Art.9", PL="Art.6", PM=("Art.5", "Art.6"),
        PS="Art.13", RA=("Art.6", "Art.8"), SA=("Art.7", "Art.28"), SC="Art.9", SI=("Art.9", "Art.10"),
        SR=("Art.28", "Art.30")),
    "CYBER_ESSENTIALS": _m(  # the five technical control themes
        AC="User access control", IA="User access control", CM="Secure configuration", SC="Firewalls",
        SI=("Security update management", "Malware protection")),
    "CIS_V8": _m(  # CIS Controls v8 control numbers 1-18
        AC=("5", "6"), AT="14", AU="8", CA="18", CM=("1", "2", "4"), CP="11", IA=("5", "6"), IR="17", MP="3",
        PT="3", RA="7", SA=("15", "16"), SC=("3", "12", "13"), SI=("7", "9", "10"), SR="15"),
    "ISO27701": _m(  # 2019 clause structure: 5 PIMS, 6 security extensions, 7 controllers, 8 processors
        AC="6.6", AT="6.4", AU="6.9", IR="6.13", PM="5.2", PT=("7.2", "7.3", "7.4", "8.2"), RA="5.4", SA="6.11",
        SR="6.12", SC="6.10"),
    "ISO27017": _m(  # cloud-specific CLD controls
        AC="CLD.9.5.1", AU="CLD.12.4.5", CM="CLD.12.1.5", MP="CLD.8.1.5", PM="CLD.6.3.1", SA="CLD.9.5.2",
        SC=("CLD.9.5.1", "CLD.13.1.4")),
    "ISO27018": _m(  # PII processor extension, annex level only
        PT="Annex A (PII processor)", SR="Annex A (subcontracted processing)", IR="Annex A (breach notification)",
        MP="Annex A (return and disposal)", SC="Annex A (encryption)"),
    "CSA_CCM": _m(  # Cloud Controls Matrix v4 domain IDs
        AC="IAM", IA="IAM", AT="HRS", PS="HRS", AU="LOG", CA="A&A", CM="CCC", CP="BCR", IR="SEF", MA="DCS",
        MP=("DSP", "DCS"), PE="DCS", PL="GRC", PM="GRC", PT="DSP", RA=("GRC", "TVM"), SA="AIS", SC=("IVS", "CEK"),
        SI=("TVM", "UEM"), SR="STA"),
    "ESSENTIAL_EIGHT": _m(  # the eight mitigation strategies
        AC="Restrict administrative privileges", IA="Multi-factor authentication",
        CM=("Application control", "Configure macro settings", "User application hardening"),
        SI=("Patch applications", "Patch operating systems"), CP="Regular backups"),
    "NYDFS_500": _m(  # 23 NYCRR Part 500 sections
        AC="500.7", AT="500.14", AU="500.6", CA="500.5", CM="500.13", CP="500.16", IA="500.12",
        IR=("500.16", "500.17"), MP="500.13", PL="500.3", PM=("500.2", "500.4"), PS="500.10", RA="500.9",
        SA="500.8", SC="500.15", SI=("500.5", "500.14"), SR="500.11"),
    "CPS_230": _m(  # APRA prudential standard, requirement areas
        PM="Governance", RA="Operational risk management", CP="Business continuity", IR="Incident management",
        SR="Service provider management", SA="Service provider management", CA="Operational risk management"),
    "EU_CRA": _m(  # Cyber Resilience Act
        SA="Annex I Part I", CM="Annex I Part I", SC="Annex I Part I", SI="Annex I Part II", RA="Annex I Part II",
        SR="Annex I Part II", IR="Art.14"),
    "CYFUN": _m(  # Belgian CyberFundamentals, built on NIST CSF functions
        AC="PR", IA="PR", AT="PR", AU="DE", CA="ID", CM="PR", CP="RC", IR="RS", MP="PR", PE="PR", PL="ID",
        PM="ID", RA="ID", SA="ID", SC="PR", SI="DE", SR="ID"),
    "TISAX": _m(  # VDA ISA assessment modules (module level only)
        AC="ISA information security", IA="ISA information security", AT="ISA information security",
        AU="ISA information security", CM="ISA information security", CP="ISA information security",
        IR="ISA information security", PE=("ISA information security", "ISA prototype protection"),
        PT="ISA data protection", SR="ISA information security", SC="ISA information security"),
    "SOX_ITGC": _m(  # IT general control domains used in SOX audits
        AC="Access to programs and data", IA="Access to programs and data", CM="Program change",
        SA="Program development", CP="Computer operations", AU="Computer operations", SI="Computer operations"),
    "ISO42001": _m(  # Annex A control objectives A.2-A.10
        PL="A.2", PM=("A.2", "A.3"), AT="A.4", RA="A.5", SA="A.6", CM="A.6", CA="A.6", AU="A.6",
        PT=("A.7", "A.8"), IR="A.3", SR="A.10", SI="A.6"),
    "NIST_AI_RMF": _m(  # AI RMF 1.0 function categories
        PM="GOVERN 1", PL="GOVERN 1", PS="GOVERN 2", AT="GOVERN 2", RA=("MAP 1", "MAP 5", "MEASURE 1"),
        CA=("MEASURE 2", "MEASURE 4"), SI=("MEASURE 2", "MANAGE 4"), AU="MEASURE 3", IR="MANAGE 4",
        SA=("GOVERN 6", "MANAGE 3"), SR=("GOVERN 6", "MANAGE 3"), PT="MEASURE 2", CM="MANAGE 2"),
    "EU_AI_ACT": _m(  # Regulation (EU) 2024/1689, high-risk obligations
        RA="Art.9", PT=("Art.10", "Art.13"), PL="Art.11", AU="Art.12", AC="Art.15", SC="Art.15", SI="Art.15",
        IR="Art.73", CA="Art.72", PM="Art.17", SA=("Art.11", "Art.17"), AT="Art.4"),
    "AIUC_1": _m(  # AIUC-1 six domains (domain level only)
        PT="A Data & Privacy", MP="A Data & Privacy", AC="B Security", IA="B Security", SC="B Security",
        SI=("B Security", "D Reliability"), RA=("C Safety", "E Accountability"), CA="D Reliability",
        CP="D Reliability", IR="E Accountability", PM="E Accountability", PL="E Accountability",
        AU="E Accountability", SA="E Accountability", SR="E Accountability", AT="F Society"),
}

# key, name, what it is, who needs it, public size of the standard, coverage
REGISTRY = (
    ("NIST_800_53", "NIST SP 800-53 Rev 5", "US federal security and privacy control catalog",
     "federal agencies and their contractors", "20 families", "native"),
    ("FEDRAMP_PROXY", "FedRAMP (proxy)", "US cloud authorization built on 800-53", "cloud providers selling to US agencies",
     "Low/Moderate/High baselines", "proxy"),
    ("SOC2", "SOC 2", "AICPA Trust Services Criteria report", "SaaS and service companies", "5 categories, CC1-CC9",
     "approximate"),
    ("ISO27001", "ISO/IEC 27001:2022", "information security management system", "global companies",
     "93 Annex A controls", "approximate"),
    ("HIPAA", "HIPAA Security Rule", "US health data security", "covered entities and business associates",
     "45 CFR 164 Subpart C", "approximate"),
    ("PCI_DSS", "PCI DSS v4.0", "card data security", "merchants and card processors", "12 requirements",
     "approximate"),
    ("GDPR", "GDPR", "EU personal data law", "anyone processing EU personal data", "99 articles", "approximate"),
    ("CCPA", "CCPA / CPRA", "California consumer privacy law", "businesses handling California residents' data",
     "Cal. Civ. Code 1798.100-199", "approximate"),
    ("COBIT", "COBIT 2019", "IT governance objectives", "IT governance and audit teams", "40 objectives", "approximate"),
    ("NIST_800_171", "NIST SP 800-171 Rev 3", "protecting CUI in non-federal systems", "federal contractors",
     "17 families, 97 requirements", "approximate"),
    ("CMMC_L2", "CMMC 2.0 Level 2", "US defense supply-chain certification", "defense contractors",
     "14 domains, 110 practices", "approximate"),
    ("NIST_CSF_2", "NIST CSF 2.0", "voluntary cybersecurity outcomes framework", "any organization",
     "6 functions, 22 categories, 106 subcategories", "approximate"),
    ("NIS2", "NIS 2 Directive", "EU cybersecurity law for essential and important entities",
     "EU critical-sector organizations", "Art. 21(2) ten measures", "approximate"),
    ("HITRUST", "HITRUST CSF", "certifiable health-sector control framework", "healthcare and their vendors",
     "14 control categories", "approximate"),
    ("DORA", "DORA", "EU digital operational resilience for finance", "EU financial entities and ICT providers",
     "5 pillars", "approximate"),
    ("CYBER_ESSENTIALS", "Cyber Essentials", "UK baseline certification", "UK government suppliers",
     "5 technical controls", "approximate"),
    ("CIS_V8", "CIS Controls v8", "prioritized security safeguards", "any organization",
     "18 controls, 153 safeguards", "approximate"),
    ("ISO27701", "ISO/IEC 27701", "privacy extension to ISO 27001", "controllers and processors of PII",
     "clauses 5-8 (2019 structure)", "approximate"),
    ("ISO27017", "ISO/IEC 27017", "cloud security controls", "cloud providers and customers", "7 CLD controls",
     "approximate"),
    ("ISO27018", "ISO/IEC 27018", "PII protection in public cloud", "public cloud PII processors", "Annex A extension",
     "approximate"),
    ("CSA_CCM", "CSA Cloud Controls Matrix v4", "cloud control framework", "cloud providers", "17 domains",
     "approximate"),
    ("ESSENTIAL_EIGHT", "Essential Eight", "Australian baseline mitigations", "Australian organizations",
     "8 strategies", "approximate"),
    ("NYDFS_500", "NYDFS 23 NYCRR 500", "New York financial cybersecurity regulation",
     "NY-regulated financial services", "Part 500 sections", "approximate"),
    ("CPS_230", "APRA CPS 230", "Australian operational risk standard", "APRA-regulated entities",
     "5 requirement areas", "approximate"),
    ("EU_CRA", "EU Cyber Resilience Act", "security of products with digital elements",
     "makers of hardware and software sold in the EU", "Annex I Parts I-II", "approximate"),
    ("CYFUN", "CyberFundamentals (CyFun)", "Belgian national cybersecurity baseline", "Belgian organizations",
     "built on NIST CSF", "approximate"),
    ("TISAX", "TISAX", "automotive information security assessment", "automotive suppliers", "VDA ISA modules",
     "approximate"),
    ("SOX_ITGC", "SOX IT general controls", "IT controls behind financial reporting", "US public companies",
     "4 ITGC domains", "approximate"),
    ("ISO42001", "ISO/IEC 42001", "AI management system", "organizations building or using AI",
     "38 Annex A controls", "approximate"),
    ("NIST_AI_RMF", "NIST AI RMF 1.0", "AI risk management framework", "AI builders and users",
     "4 functions", "approximate"),
    ("EU_AI_ACT", "EU AI Act", "EU AI regulation", "providers and deployers of AI in the EU",
     "high-risk obligations Art. 9-17", "approximate"),
    ("AIUC_1", "AIUC-1", "AI agent assurance standard", "AI agent vendors", "6 domains", "approximate"),
    ("CUSTOM", "Custom framework", "your own control set", "anyone", "user defined", "covered (custom.py)"),
    ("MS_SSPA", "Supplier privacy program (one platform vendor)", "a supplier data-protection program run by one large "
     "software vendor", "that vendor's suppliers", "vendor-specific requirement list", "gap"),
)
REGISTRY_KEYS = tuple(r[0] for r in REGISTRY)
CORE = tuple(f for f in crosswalk.FRAMEWORKS)
ALL_MAPPED = CORE + tuple(EXT_MAP)


def info(key: str) -> dict:
    for r in REGISTRY:
        if r[0] == key:
            return dict(zip(("key", "name", "what", "who", "public_size", "coverage"), r))
    raise KeyError(key)


@lru_cache(maxsize=None)
def map_control(cid: str) -> dict[str, tuple[str, ...]]:
    c = catalog.by_id()[cid]
    out = dict(crosswalk.map_control(cid))
    for fw, fam in EXT_MAP.items():
        out[fw] = fam.get(c.family, ())
    return out


def mapped_controls(fw: str, baseline: str = "ae") -> list[str]:
    if fw == "NIST_800_53":
        return [c.id for c in catalog.baseline(baseline)]
    return [c.id for c in catalog.baseline(baseline) if map_control(c.id).get(fw)]


def unmapped_families(fw: str) -> list[str]:
    if fw in EXT_MAP:
        return [f for f in FAM if f not in EXT_MAP[fw]]
    return []


def readiness(by_control: dict | None = None, frameworks=None) -> list[dict]:
    """Per framework: mapped controls, ready (tested and passing), failing, untested, ready %.
    Computed from the synthetic assessment run, nothing else."""
    if by_control is None:
        from .. import assess
        by_control = assess.by_control()
    rows = []
    for fw in frameworks or [k for k in REGISTRY_KEYS if k in ALL_MAPPED or k == "NIST_800_53"]:
        ids = mapped_controls(fw)
        st = [by_control.get(c, {}).get("status", "not_tested") for c in ids]
        ready, failing = st.count("pass"), st.count("fail")
        rows.append({"framework": fw, "name": info(fw)["name"], "controls": len(ids), "ready": ready,
                     "failing": failing, "untested": len(ids) - ready - failing,
                     "ready_pct": round(100 * ready / len(ids), 1) if ids else 0.0,
                     "coverage": info(fw)["coverage"]})
    return rows


def coverage_table() -> str:
    lines = ["| Framework | What it is | Who needs it | Public size | Mapped AE controls | Coverage |",
             "|---|---|---|---|---:|---|"]
    for r in REGISTRY:
        key = r[0]
        n = len(mapped_controls(key)) if (key in ALL_MAPPED or key == "NIST_800_53") else "-"
        lines.append(f"| {r[1]} | {r[2]} | {r[3]} | {r[4]} | {n} | {r[5]} |")
    return "\n".join(lines)


def readiness_table() -> str:
    lines = ["| Framework | Ready / mapped | Ready % | Failing | Untested |", "|---|---:|---:|---:|---:|"]
    for r in readiness():
        lines.append(f"| {r['name']} | {r['ready']} / {r['controls']} | {r['ready_pct']}% | {r['failing']} | "
                     f"{r['untested']} |")
    return "\n".join(lines)


def summary() -> dict:
    cov: dict[str, int] = {}
    for r in REGISTRY:
        k = r[5].split(" ")[0]
        cov[k] = cov.get(k, 0) + 1
    return {"frameworks": len(REGISTRY), "by_coverage": cov}
