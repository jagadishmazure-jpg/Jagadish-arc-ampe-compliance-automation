"""Shared responsibility matrix: platform vendor vs Microsoft Azure vs customer, per control family.

Codes: P = primary owner, S = shared (does part of it), I = inherits from another party, - = none.
"Platform vendor" means whoever operates this compliance automation platform as a service.
"Customer" is the state exchange (here the fictional Lakehaven Health Connector).
This is a design proposal for a self-assessment, not a contract.
"""
from __future__ import annotations

import csv
import io

from .. import catalog

PARTIES = ("platform_vendor", "azure", "customer")
MATRIX: dict[str, tuple[str, str, str, str]] = {
    # family: (vendor, azure, customer, what each side does)
    "AC": ("S", "S", "P", "Vendor builds RBAC and tenant isolation; Azure provides Entra ID; customer assigns roles and reviews access"),
    "AT": ("S", "-", "P", "Vendor trains its own staff; customer trains its workforce"),
    "AU": ("P", "S", "S", "Vendor keeps the hash-chained audit trail; Azure Monitor stores logs; customer reviews weekly"),
    "CA": ("S", "I", "P", "Customer owns the ATO and assessments; vendor supplies its own assessment evidence"),
    "CM": ("P", "S", "S", "Vendor runs change control for the platform; customer controls its own configs"),
    "CP": ("P", "S", "S", "Vendor backs up and restore-tests the platform; Azure supplies zone redundancy"),
    "IA": ("S", "P", "S", "Entra ID authenticates; vendor enforces MFA for privileged actions; customer manages users"),
    "IR": ("S", "S", "P", "Each party handles its own incidents; vendor notifies customer within 1 hour"),
    "MA": ("S", "P", "-", "Azure maintains hardware; vendor patches platform software"),
    "MP": ("-", "P", "S", "Azure sanitizes physical media; customer handles its own exports"),
    "PE": ("-", "P", "-", "Fully inherited from Azure data centers"),
    "PL": ("S", "-", "P", "Customer owns the SSPP; vendor provides the platform system description"),
    "PM": ("-", "-", "P", "Program management is the customer's"),
    "PS": ("S", "S", "P", "Each party screens and offboards its own people"),
    "PT": ("S", "-", "P", "Customer decides PII purposes and notices; vendor redacts PII before AI prompts"),
    "RA": ("S", "S", "P", "Customer owns risk decisions; vendor scans the platform"),
    "SA": ("P", "S", "S", "Vendor runs secure development; customer manages acquisition of the platform"),
    "SC": ("P", "S", "S", "Vendor encrypts and isolates; Azure supplies network and key services"),
    "SI": ("P", "S", "S", "Vendor patches and monitors the platform; customer monitors its own estate"),
    "SR": ("S", "S", "P", "Customer manages its supply chain; vendor manages its own sub-processors"),
}


def rows() -> list[dict]:
    names = {c.family: c.family_name for c in catalog.load()}
    counts: dict[str, int] = {}
    for c in catalog.baseline("ae"):
        counts[c.family] = counts.get(c.family, 0) + 1
    return [{"family": f, "family_name": names[f], "controls": counts.get(f, 0), "platform_vendor": v,
             "azure": a, "customer": cu, "notes": n} for f, (v, a, cu, n) in MATRIX.items()]


def to_csv() -> str:
    buf = io.StringIO()
    r = rows()
    w = csv.DictWriter(buf, fieldnames=list(r[0]), lineterminator="\n")
    w.writeheader()
    w.writerows(r)
    return buf.getvalue()


def to_markdown() -> str:
    out = ["| Family | Controls | Platform vendor | Azure | Customer | Notes |", "|---|---:|:-:|:-:|:-:|---|"]
    for r in rows():
        out.append(f"| {r['family']} {r['family_name']} | {r['controls']} | {r['platform_vendor']} | {r['azure']} | "
                   f"{r['customer']} | {r['notes']} |")
    return "\n".join(out)


def primary_counts() -> dict[str, int]:
    """How many AE controls sit in families where each party is primary."""
    out = dict.fromkeys(PARTIES, 0)
    for r in rows():
        for p in PARTIES:
            if r[p] == "P":
                out[p] += r["controls"]
    return out
