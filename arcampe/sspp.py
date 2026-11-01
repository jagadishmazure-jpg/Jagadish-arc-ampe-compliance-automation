"""Excel SSPP export (openpyxl), shaped like the ARC-AMPE Vol II workbook but with no CMS text.

Sheets: Cover, Controls (one row per AE control), POA&M, Attestations, Crosswalk, Summary.
Only human-approved implementation statements are written; others say "Pending approval".
The file is made byte-for-byte reproducible by fixing workbook and zip timestamps.
"""
from __future__ import annotations

import datetime as dt
import io
import re
import zipfile

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from . import ENTITY, TODAY, agent, assess, attest, catalog, crosswalk, poam
from .platform.responsibility import MATRIX

HEADER_FILL = PatternFill("solid", fgColor="1F3864")
FIXED = dt.datetime(2026, 10, 31, 0, 0, 0)
STATUS_FILL = {"pass": "C6EFCE", "fail": "FFC7CE", "not tested": "FFEB9C"}


def _sheet(wb, title, header, rows, widths=None):
    ws = wb.create_sheet(title)
    ws.append(header)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = HEADER_FILL
        c.alignment = Alignment(wrap_text=True, vertical="top")
    for r in rows:
        ws.append(r)
    ws.freeze_panes = "A2"
    for i, w in enumerate(widths or [], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    return ws


def build(findings=None) -> Workbook:
    findings = assess.run_all() if findings is None else findings
    byc = assess.by_control(findings)
    approvals = agent.load_approvals()
    atts = {a.control: a for a in attest.load()}
    items = poam.build(findings)
    wb = Workbook()
    wb.remove(wb.active)
    wb.properties.creator = "arcampe (synthetic demo)"
    wb.properties.created = FIXED
    wb.properties.modified = FIXED
    _sheet(wb, "Cover", ["Field", "Value"], [
        ["Entity", f"{ENTITY} (fictional)"], ["System", "Eligibility and Enrollment (synthetic)"],
        ["Baseline", "ARC-AMPE ACA Administering Entity (AE) - control IDs from the public CMS workbook v1.02"],
        ["Generated", TODAY], ["Data", "All results come from synthetic fixtures. Not a real SSPP."],
        ["Control text", "Not included. Use the official CMS workbook for control and parameter text."]],
        [18, 100])
    rows = []
    for c in catalog.baseline("ae"):
        r = byc.get(c.id)
        status = r["status"] if r else "not tested"
        if c.label == "attestation" and c.id in atts:
            status = "pass" if atts[c.id].status() in ("current", "due_soon") else "fail"
        appr = approvals.get(c.id)
        stmt = appr["text"] if appr and appr["status"] == "approved" else "Pending approval"
        resp = MATRIX[c.family]
        rows.append([c.id, c.family, c.title, "Yes" if c.dee else "No", c.label, status,
                     r["passed"] if r else 0, r["failed"] if r else 0, stmt,
                     appr["approver"] if appr else "", f"vendor {resp[0]} / azure {resp[1]} / customer {resp[2]}"])
    ws = _sheet(wb, "Controls", ["Control", "Family", "Title (NIST)", "In DEE (unverified)", "Label", "Status",
                                 "Passing results", "Failing results", "Implementation statement (approved only)",
                                 "Approved by", "Responsibility"], rows, [12, 7, 40, 10, 12, 11, 9, 9, 80, 12, 34])
    for row in ws.iter_rows(min_row=2):
        row[5].fill = PatternFill("solid", fgColor=STATUS_FILL[row[5].value])
        row[8].alignment = Alignment(wrap_text=True, vertical="top")
    _sheet(wb, "POA&M", ["ID", "Check", "Resource", "Weakness", "Controls", "Severity", "First seen", "Due",
                         "Days open", "SLA", "Owner", "Milestones"],
           [list(i.row().values()) for i in items], [15, 8, 26, 50, 22, 9, 11, 11, 8, 9, 16, 60])
    _sheet(wb, "Attestations", ["Control", "Owner", "Every (days)", "Last attested", "Status", "Evidence"],
           [[a.control, a.owner, a.frequency_days, a.last_attested or "", a.status(), a.evidence_ref or ""]
            for a in attest.load()], [12, 20, 10, 12, 10, 36])
    _sheet(wb, "Crosswalk", ["Control", *crosswalk.FRAMEWORKS],
           [[c.id, *[", ".join(v) for v in crosswalk.map_control(c.id).values()]] for c in catalog.baseline("ae")],
           [12] + [24] * len(crosswalk.FRAMEWORKS))
    st = {"pass": 0, "fail": 0, "not tested": 0}
    for r in rows:
        st[r[5]] += 1
    _sheet(wb, "Summary", ["Metric", "Value"], [
        ["Controls", len(rows)], ["Pass", st["pass"]], ["Fail", st["fail"]], ["Not tested", st["not tested"]],
        ["Open POA&M items", len(items)], ["Approved statements", len(approvals)]], [28, 12])
    return wb


def to_bytes(wb: Workbook) -> bytes:
    raw = io.BytesIO()
    wb.save(raw)
    src = zipfile.ZipFile(io.BytesIO(raw.getvalue()))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for info in sorted(src.infolist(), key=lambda i: i.filename):
            zi = zipfile.ZipInfo(info.filename, date_time=(2026, 10, 31, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            data = src.read(info.filename)
            if info.filename == "docProps/core.xml":   # openpyxl stamps "modified" with the wall clock
                data = re.sub(rb"(<dcterms:modified[^>]*>)[^<]*", rb"\g<1>2026-10-31T00:00:00Z", data)
            z.writestr(zi, data)
    return out.getvalue()


def status_counts(wb: Workbook) -> dict:
    ws = wb["Controls"]
    out: dict[str, int] = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        out[row[5]] = out.get(row[5], 0) + 1
    return out
