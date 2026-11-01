"""Author-built crosswalks from ARC-AMPE / NIST 800-53 controls to other frameworks.

These are NOT official mappings. They are a starting point written for this demo at family level,
with control-level overrides where the match is specific. Reference IDs only; no framework text.
FedRAMP is a proxy: "in the NIST SP 800-53B Moderate baseline" (FedRAMP Rev5 OSCAL was not fetched).
"""
from __future__ import annotations

from collections import Counter
from functools import lru_cache

from . import catalog

FRAMEWORKS = ("HIPAA", "SOC2", "ISO27001", "PCI_DSS", "GDPR", "CCPA", "COBIT", "FEDRAMP_PROXY")

FAMILY_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "HIPAA": {  # 45 CFR 164 Security Rule sections
        "AC": ("164.312(a)(1)", "164.308(a)(4)"), "AT": ("164.308(a)(5)",), "AU": ("164.312(b)",),
        "CA": ("164.308(a)(8)",), "CM": ("164.308(a)(1)(ii)(B)",), "CP": ("164.308(a)(7)",),
        "IA": ("164.312(d)",), "IR": ("164.308(a)(6)",), "MA": ("164.310(a)(2)(iv)",),
        "MP": ("164.310(d)(1)",), "PE": ("164.310(a)(1)",), "PL": ("164.316(a)",), "PM": ("164.308(a)(2)",),
        "PS": ("164.308(a)(3)",), "PT": ("164.530(c)",), "RA": ("164.308(a)(1)(ii)(A)",),
        "SA": ("164.308(b)(1)",), "SC": ("164.312(e)(1)",), "SI": ("164.308(a)(5)(ii)(B)",),
        "SR": ("164.314(a)(1)",)},
    "SOC2": {  # 2017 Trust Services Criteria IDs
        "AC": ("CC6.1", "CC6.2", "CC6.3"), "AT": ("CC1.4", "CC2.2"), "AU": ("CC7.2",), "CA": ("CC4.1", "CC4.2"),
        "CM": ("CC8.1",), "CP": ("A1.2", "A1.3"), "IA": ("CC6.1",), "IR": ("CC7.3", "CC7.4", "CC7.5"),
        "MA": ("CC8.1",), "MP": ("CC6.5", "CC6.7"), "PE": ("CC6.4",), "PL": ("CC5.3",), "PM": ("CC1.1", "CC3.1"),
        "PS": ("CC1.4", "CC6.2"), "PT": ("P1.1", "P3.1", "P4.1"), "RA": ("CC3.2", "CC7.1"), "SA": ("CC8.1", "CC9.2"),
        "SC": ("CC6.6", "CC6.7"), "SI": ("CC7.1", "CC7.2"), "SR": ("CC9.2",)},
    "ISO27001": {  # ISO/IEC 27001:2022 Annex A control IDs
        "AC": ("A.5.15", "A.5.18", "A.8.2"), "AT": ("A.6.3",), "AU": ("A.8.15", "A.8.17"), "CA": ("A.5.35", "A.5.36"),
        "CM": ("A.8.9", "A.8.32"), "CP": ("A.5.29", "A.5.30", "A.8.13"), "IA": ("A.5.16", "A.5.17", "A.8.5"),
        "IR": ("A.5.24", "A.5.25", "A.5.26"), "MA": ("A.7.13",), "MP": ("A.7.10", "A.7.14"),
        "PE": ("A.7.1", "A.7.2", "A.7.4"), "PL": ("A.5.1",), "PM": ("A.5.1", "A.5.4"), "PS": ("A.6.1", "A.6.5"),
        "PT": ("A.5.34",), "RA": ("A.8.8",), "SA": ("A.8.25", "A.8.28", "A.8.29"), "SC": ("A.8.20", "A.8.24"),
        "SI": ("A.8.7", "A.8.16"), "SR": ("A.5.19", "A.5.21")},
    "PCI_DSS": {  # PCI DSS v4.0 principal requirements
        "AC": ("7", "8"), "AT": ("12.6",), "AU": ("10",), "CA": ("11", "12.4"), "CM": ("2", "6.5"),
        "CP": ("12.10.1",), "IA": ("8",), "IR": ("12.10",), "MA": ("9.5",), "MP": ("9.4",), "PE": ("9",),
        "PL": ("12.1",), "PM": ("12",), "PS": ("12.7",), "PT": ("3.2",), "RA": ("12.3", "6.3"), "SA": ("6.2", "12.8"),
        "SC": ("1", "4"), "SI": ("5", "6.3", "11.5"), "SR": ("12.8",)},
    "GDPR": {  # article numbers
        "AC": ("Art.32",), "AU": ("Art.30", "Art.32"), "CP": ("Art.32(1)(c)",), "IR": ("Art.33", "Art.34"),
        "MP": ("Art.32",), "PM": ("Art.24", "Art.37"), "PT": ("Art.5", "Art.6", "Art.7", "Art.13"),
        "RA": ("Art.35",), "SA": ("Art.25", "Art.28"), "SC": ("Art.32(1)(a)",), "SR": ("Art.28",)},
    "CCPA": {  # Cal. Civ. Code sections
        "AC": ("1798.150",), "IR": ("1798.82",), "PT": ("1798.100", "1798.105", "1798.120", "1798.130"),
        "SA": ("1798.140(ag)",), "SC": ("1798.150",), "SR": ("1798.100(d)",), "PM": ("1798.185",)},
    "COBIT": {  # COBIT 2019 objectives
        "AC": ("DSS05.04",), "AT": ("APO07.03",), "AU": ("DSS05.07",), "CA": ("MEA02", "MEA04"), "CM": ("BAI06", "BAI10"),
        "CP": ("DSS04",), "IA": ("DSS05.04",), "IR": ("DSS02",), "MA": ("DSS01",), "MP": ("DSS05.06",),
        "PE": ("DSS05.05",), "PL": ("APO01",), "PM": ("EDM03", "APO12"), "PS": ("APO07",), "PT": ("APO14",),
        "RA": ("APO12",), "SA": ("BAI03", "APO10"), "SC": ("DSS05.02",), "SI": ("DSS05.01",), "SR": ("APO10",)},
}

OVERRIDES: dict[str, dict[str, tuple[str, ...]]] = {
    "HIPAA": {"AU-11": ("164.316(b)(2)(i)",), "SC-08": ("164.312(e)(1)", "164.312(e)(2)(ii)"),
              "SC-28": ("164.312(a)(2)(iv)",), "AC-11": ("164.312(a)(2)(iii)",), "IA-02(01)": ("164.312(d)",),
              "CP-09": ("164.308(a)(7)(ii)(A)",), "AU-06": ("164.308(a)(1)(ii)(D)",)},
    "SOC2": {"CM-03": ("CC8.1",), "CP-09": ("A1.2",), "CP-04": ("A1.3",), "RA-05": ("CC7.1",), "PS-04": ("CC6.2",)},
    "ISO27001": {"CP-09": ("A.8.13",), "SC-28": ("A.8.24",), "RA-05": ("A.8.8",), "AU-11": ("A.5.33",),
                 "SA-09(05)": ("A.5.23",), "SR-03": ("A.5.21",), "IA-02(01)": ("A.8.5",)},
    "PCI_DSS": {"RA-05": ("11.3",), "SI-02": ("6.3.3",), "CA-08": ("11.4",), "AU-11": ("10.5.1",),
                "IA-02(01)": ("8.4",), "AC-11": ("8.2.8",), "AC-07": ("8.3.4",), "SC-28": ("3.5",), "SC-08": ("4.2",)},
    "GDPR": {"SA-09(05)": ("Art.44",), "PT-04": ("Art.7",), "RA-08": ("Art.35",), "IR-06": ("Art.33",)},
}


@lru_cache(maxsize=None)
def _ids() -> dict:
    return catalog.by_id()


def map_control(cid: str) -> dict[str, tuple[str, ...]]:
    c = _ids()[cid]
    out = {}
    for fw in FRAMEWORKS:
        if fw == "FEDRAMP_PROXY":
            out[fw] = ("Moderate",) if c.nist_moderate else ()
            continue
        out[fw] = OVERRIDES.get(fw, {}).get(cid) or FAMILY_MAP[fw].get(c.family, ())
    return out


def coverage(baseline: str = "ae") -> dict[str, dict]:
    rows = catalog.baseline(baseline)
    out = {}
    for fw in FRAMEWORKS:
        mapped = [c for c in rows if map_control(c.id)[fw]]
        refs = {r for c in rows for r in map_control(c.id)[fw]}
        links = sum(len(map_control(c.id)[fw]) for c in rows)
        out[fw] = {"controls_mapped": len(mapped), "of": len(rows), "distinct_refs": len(refs), "links": links,
                   "override_count": len(OVERRIDES.get(fw, {}))}
    return out


def reverse(fw: str, baseline: str = "ae") -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for c in catalog.baseline(baseline):
        for r in map_control(c.id)[fw]:
            out.setdefault(r, []).append(c.id)
    return out


def relationship_counts(baseline: str = "ae") -> Counter:
    """Cartography-style count: how many framework requirements each control family links to."""
    cnt: Counter = Counter()
    for c in catalog.baseline(baseline):
        for fw, refs in map_control(c.id).items():
            if refs:
                cnt[(c.family, fw)] += len(refs)
    return cnt


def coverage_table(baseline: str = "ae") -> str:
    rows = ["| Framework | Controls mapped | Distinct requirement IDs | Links | Control-level overrides |",
            "|---|---:|---:|---:|---:|"]
    for fw, d in coverage(baseline).items():
        rows.append(f"| {fw} | {d['controls_mapped']} / {d['of']} | {d['distinct_refs']} | {d['links']} | "
                    f"{d['override_count']} |")
    return "\n".join(rows)
