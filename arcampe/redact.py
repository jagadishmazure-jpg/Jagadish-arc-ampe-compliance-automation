"""PII redaction applied to any text before it reaches a model prompt or a log."""
from __future__ import annotations

import re

from .privacy import SSN_RE, valid_ssn

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b")
PHONE_RE = re.compile(r"(?<!\d)(\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4})(?!\d)")
DOB_RE = re.compile(r"\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b(?=.{0,20}\b(dob|birth))", re.I)
MEDICAID_RE = re.compile(r"\b(MID|Medicaid ID)[:# ]*\w{8,12}\b", re.I)


def redact(text: str) -> tuple[str, dict[str, int]]:
    counts = {"ssn": 0, "email": 0, "phone": 0, "dob": 0, "medicaid_id": 0}

    def ssn(m):
        if valid_ssn(*m.groups()):
            counts["ssn"] += 1
            return "[SSN]"
        return m.group(0)

    text = SSN_RE.sub(ssn, text)
    for name, rx, tag in (("email", EMAIL_RE, "[EMAIL]"), ("phone", PHONE_RE, "[PHONE]"), ("dob", DOB_RE, "[DOB]"),
                          ("medicaid_id", MEDICAID_RE, "[MEDICAID_ID]")):
        text, n = rx.subn(tag, text)
        counts[name] += n
    return text, counts
