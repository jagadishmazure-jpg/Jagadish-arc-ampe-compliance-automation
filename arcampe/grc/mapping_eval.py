"""Control-mapping eval harness (A10): four synthetic test types and mean reciprocal rank.

From each labeled item we derive four queries:
  exact      - the original text
  paraphrase - common words swapped for synonyms the mapper's keyword lists may not contain
  partial    - only the first half of the words
  keyword    - only the three longest words
Each query is ranked against every control by the existing mapper. We report top-1, top-3 and MRR (1 / rank of
the correct control; 0 if it is not in the top 10). These are measured numbers on synthetic text, not claims.
"""
from __future__ import annotations

import re

from ..integrations import mapper

TYPES = ("exact", "paraphrase", "partial", "keyword")
SYNONYMS = {"accounts": "identities", "account": "identity", "report": "listing", "disabled": "turned off",
            "backup": "copy", "backups": "copies", "encryption": "encoding", "encrypted": "protected",
            "logs": "records", "log": "record", "users": "people", "user": "person", "training": "course",
            "review": "check", "vulnerability": "weakness", "scan": "sweep", "firewall": "network filter",
            "password": "passphrase", "incident": "event", "policy": "rule set", "access": "entry"}
MAX_RANK = 10


def variants(text: str) -> dict:
    words = text.split()
    para = " ".join(SYNONYMS.get(w.lower().strip(".,()"), w) for w in words)
    longest = sorted({re.sub(r"[^A-Za-z0-9\-]", "", w) for w in words}, key=lambda w: (-len(w), w))[:3]
    return {"exact": text, "paraphrase": para, "partial": " ".join(words[: max(1, len(words) // 2)]),
            "keyword": " ".join(longest)}


def rank(text: str, label: str) -> int | None:
    ranked = [c for c, s in mapper._score(text) if s > 0]
    return ranked.index(label) + 1 if label in ranked[:MAX_RANK] else None


def run(items=None) -> dict:
    items = items or mapper.load_labeled()
    out = {}
    for t in TYPES:
        ranks = [rank(variants(it["text"])[t], it["label"]) for it in items]
        n = len(ranks)
        out[t] = {"queries": n, "top1": round(sum(r == 1 for r in ranks) / n, 3),
                  "top3": round(sum(r is not None and r <= 3 for r in ranks) / n, 3),
                  "mrr": round(sum(1 / r for r in ranks if r) / n, 3),
                  "missed": sum(r is None for r in ranks)}
    return {"by_type": out, "label": "measured on synthetic labeled items"}
