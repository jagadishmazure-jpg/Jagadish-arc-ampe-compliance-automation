"""Challenge: inconsistent scoring. One normalized 0-10 scale and one banding for every source."""
from __future__ import annotations

BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "moderate"), (0.1, "low"), (0.0, "none"))
WORDS = {"critical": 9.5, "very high": 9.0, "high": 7.5, "medium": 5.0, "moderate": 5.0, "low": 2.5,
         "informational": 0.0, "info": 0.0, "none": 0.0}


def band(score: float) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "none"


def normalize(source: str, value) -> float:
    """Map a source-native severity onto 0-10.

    cvss / tenable: CVSS base score as is. qualys: severity 1-5 -> 2,4,6,8,10.
    defender, aws, gcp, internal words: fixed table. likelihood x impact (1-25) -> /2.5.
    """
    s = source.lower()
    if s in ("cvss", "tenable"):
        v = float(value)
    elif s == "qualys":
        v = {1: 2.0, 2: 4.0, 3: 6.0, 4: 8.0, 5: 10.0}[int(value)]
    elif s in ("lxi", "risk_matrix"):
        v = float(value) / 2.5
    else:
        v = WORDS[str(value).lower()]
    if not 0.0 <= v <= 10.0:
        raise ValueError(f"out of range: {source} {value}")
    return round(v, 2)


def normalize_finding(f) -> dict:
    s = normalize("internal", f.severity)
    return {"check": f.check_id, "resource": f.resource_name, "native": f.severity, "score": s, "band": band(s)}
