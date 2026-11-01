"""Prompt-injection screen shared by the drafting agent and the secure-AI prompt preparation.

Kept in its own module so arcampe.agent and arcampe.platform.secure_ai do not import each other.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore (all|any|the)? ?(previous|prior|above) instructions", r"disregard (the )?(system|previous)",
    r"you are now", r"act as (an? )?(admin|administrator|system)", r"reveal (the |your |any )?(system prompt|secrets?|keys?)",
    r"mark (this|all|the) controls? as (pass|passed|compliant|implemented)", r"approve (this|it) automatically",
    r"<\s*/?\s*(system|assistant)\s*>", r"BEGIN (SYSTEM|ADMIN) PROMPT",
]
_INJ = re.compile("|".join(INJECTION_PATTERNS), re.I)


def screen(text: str) -> list[str]:
    """Return every injection-pattern match in the text (empty list means clean)."""
    return [m.group(0) for m in _INJ.finditer(text)]
