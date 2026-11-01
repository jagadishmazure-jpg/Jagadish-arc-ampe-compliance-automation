"""Rebuild data/catalog/catalog.json from public sources (run by hand, not in CI).

Inputs (download them yourself, they are not committed):
  --oscal-dir   folder with the NIST SP 800-53 Rev 5 OSCAL catalog and 800-53B baseline
                profiles from github.com/usnistgov/oscal-content (nist.gov/SP800-53/rev5/json)
  --ae-xlsx     the public CMS workbook "ARC-AMPE Vol II SSPP - ACA AE v1.02" from
                cms.gov/marketplace/resources/regulations-guidance (sheet "AE Mandatory Baseline")
  --dee-ids     a JSON list of DEE control IDs (see data/baselines/dee.json for provenance)

Only control identifiers are read from the CMS workbook. Titles come from the NIST catalog.
No CMS control text is copied into this repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
CMS_ID = re.compile(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$")


def cms_to_oscal(cms_id: str) -> str:
    m = CMS_ID.match(cms_id.strip())
    if not m:
        raise ValueError(cms_id)
    base = f"{m[1].lower()}-{int(m[2])}"
    return base + (f".{int(m[3])}" if m[3] else "")


def canonical(cms_id: str) -> str:
    """AC-2(3) / AC-02(03) -> AC-02(03) (the zero-padded style CMS uses)."""
    m = CMS_ID.match(cms_id.strip())
    if not m:
        raise ValueError(cms_id)
    return f"{m[1]}-{int(m[2]):02d}" + (f"({int(m[3]):02d})" if m[3] else "")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_oscal(d: pathlib.Path) -> tuple[dict, dict]:
    cat = json.loads((d / "NIST_SP-800-53_rev5_catalog.json").read_text())["catalog"]
    controls: dict[str, tuple[str, str]] = {}

    def walk(ctrl: dict, fam: str) -> None:
        controls[ctrl["id"]] = (ctrl["title"], fam)
        for sub in ctrl.get("controls", []):
            walk(sub, fam)

    for g in cat["groups"]:
        for ctrl in g.get("controls", []):
            walk(ctrl, g["title"])
    baselines = {}
    for name in ("LOW", "MODERATE", "HIGH", "PRIVACY"):
        prof = json.loads((d / f"NIST_SP-800-53_rev5_{name}-baseline_profile.json").read_text())["profile"]
        ids = set()
        for imp in prof["imports"]:
            for inc in imp.get("include-controls", []):
                ids.update(inc.get("with-ids", []))
        baselines[name.lower()] = ids
    return controls, baselines


def ae_ids(xlsx: pathlib.Path) -> list[str]:
    import openpyxl

    wb = openpyxl.load_workbook(xlsx, read_only=True)
    out = []
    for row in wb["AE Mandatory Baseline"].iter_rows(values_only=True):
        if row[0] is not None and str(row[0]).strip().isdigit():
            out.append(canonical(str(row[2])))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oscal-dir", required=True, type=pathlib.Path)
    ap.add_argument("--ae-xlsx", required=True, type=pathlib.Path)
    ap.add_argument("--dee-ids", required=True, type=pathlib.Path)
    a = ap.parse_args()
    controls, baselines = load_oscal(a.oscal_dir)
    ae = ae_ids(a.ae_xlsx)
    dee = sorted({canonical(x) for x in json.loads(a.dee_ids.read_text())})
    rows = []
    for cid in ae:
        oid = cms_to_oscal(cid)
        title, fam = controls[oid]
        rows.append({
            "id": cid, "oscal_id": oid, "family": cid[:2], "family_name": fam, "title": title,
            "enhancement": "(" in cid, "ae": True, "dee": cid in dee,
            "nist_low": oid in baselines["low"], "nist_moderate": oid in baselines["moderate"],
            "nist_high": oid in baselines["high"], "nist_privacy": oid in baselines["privacy"],
        })
    out = ROOT / "data" / "catalog" / "catalog.json"
    out.write_text(json.dumps({
        "sources": {
            "nist_catalog": "usnistgov/oscal-content NIST_SP-800-53_rev5_catalog.json",
            "nist_catalog_sha256": sha256(a.oscal_dir / "NIST_SP-800-53_rev5_catalog.json"),
            "ae_workbook": "CMS ARC-AMPE Vol II SSPP ACA AE v1.02 (public, cms.gov)",
            "ae_workbook_sha256": sha256(a.ae_xlsx),
            "dee_ids": "third-party public parse of the CMS DEE workbook; not verified against the CMS file",
        },
        "controls": rows,
    }, indent=1) + "\n")
    print(f"wrote {len(rows)} controls ({sum(r['dee'] for r in rows)} also in DEE) -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
