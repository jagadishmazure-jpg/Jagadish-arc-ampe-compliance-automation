"""Write two fictional OpenAPI specs that drive the generic OpenAPI connector."""
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "openapi"


def ok(example: dict) -> dict:
    return {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object"},
                                                                          "example": example}}}}


ASSETS = [
    {"assetTag": "LHX-SRV-001", "hostname": "vm-lhx-app01", "owner": "cloud-platform", "criticality": "high",
     "lastSeen": "2026-10-30", "os": "Ubuntu 24.04", "pii": True},
    {"assetTag": "LHX-SRV-002", "hostname": "vm-lhx-app02", "owner": "cloud-platform", "criticality": "high",
     "lastSeen": "2026-10-30", "os": "Ubuntu 24.04", "pii": True},
    {"assetTag": "LHX-LAP-114", "hostname": "lt-114", "owner": None, "criticality": "low",
     "lastSeen": "2026-07-02", "os": "Windows 11", "pii": False},
    {"assetTag": "LHX-NET-007", "hostname": "fw-lhx-edge", "owner": "network", "criticality": "high",
     "lastSeen": "2026-10-31", "os": "PAN-OS 11", "pii": False},
]
CMDB = {
    "openapi": "3.0.3",
    "info": {"title": "Pinecrest Asset Registry", "version": "1.4.0",
             "description": "Fictional CMDB API used to show the OpenAPI connector."},
    "paths": {"/v1/assets": {
        "get": {"operationId": "listAssets", "summary": "List assets",
                "parameters": [{"name": "page", "in": "query", "schema": {"type": "integer"}}],
                "responses": ok({"data": {"assets": ASSETS}})},
        "post": {"operationId": "createAsset", "responses": {"201": {"description": "created"}}}}},
    "x-arcampe": {"name": "pinecrest_cmdb", "category": "openapi", "operationId": "listAssets",
                  "records": "data.assets", "kind": "asset", "subject": "hostname", "observed_at": "lastSeen",
                  "attributes": {"owner": "owner", "criticality": "criticality", "os": "os", "pii": "pii",
                                 "asset_tag": "assetTag"},
                  "control_hints": ["CM-08", "CM-08(01)"]},
}
LMS = {
    "openapi": "3.1.0",
    "info": {"title": "Brightpath Learning", "version": "2.0.0",
             "description": "Fictional learning platform API used to show the OpenAPI connector."},
    "paths": {"/api/completions": {"get": {"operationId": "listCompletions", "responses": ok({"items": [
        {"user": "user001@lakehaven-hx.example", "course": "Privacy and security awareness 2026",
         "completedOn": "2026-02-11"},
        {"user": "user002@lakehaven-hx.example", "course": "Privacy and security awareness 2026",
         "completedOn": "2025-09-03"},
        {"user": "user003@lakehaven-hx.example", "course": "Role-based training: administrators",
         "completedOn": "2026-05-19"}]})}}},
    "x-arcampe": {"name": "brightpath_lms", "category": "openapi", "operationId": "listCompletions",
                  "records": "items", "kind": "training", "subject": "user", "observed_at": "completedOn",
                  "attributes": {"course": "course"}, "control_hints": ["AT-02", "AT-03"]},
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for n, s in (("pinecrest_cmdb", CMDB), ("brightpath_lms", LMS)):
        (OUT / f"{n}.json").write_text(json.dumps(s, indent=1) + "\n")
    print("wrote 2 specs")
