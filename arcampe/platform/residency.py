"""US-only data residency (SA-09(05)): every store holding customer data must sit in a U.S. region."""
from __future__ import annotations

from ..params import US_REGIONS

DATA_TYPES = ("Microsoft.Storage/storageAccounts", "Microsoft.Sql/servers", "Microsoft.DocumentDB/databaseAccounts",
              "Microsoft.KeyVault/vaults", "Microsoft.Search/searchServices",
              "Microsoft.CognitiveServices/accounts", "Microsoft.OperationalInsights/workspaces")


def check(resources: list[dict]) -> list[dict]:
    out = []
    for r in resources:
        if r["type"] not in DATA_TYPES:
            continue
        locs = {r["location"], *r.get("properties", {}).get("geoReplicaLocations", [])}
        bad = sorted(loc for loc in locs if loc not in US_REGIONS)
        out.append({"resource": r["name"], "locations": sorted(locs), "ok": not bad, "outside_us": bad})
    return out
