import json

import pytest

from arcampe.integrations import connectors, mapper, nocode, openapi, schema, webhooks
from arcampe.integrations.sdk import NetworkDisabled


def test_evidence_hash_and_lineage():
    e = schema.make("t1", "src", "cloud", "k", "s", "2026-10-30", {"a": 1})
    assert e.evidence_id == f"ev-{e.content_sha256[:16]}" and schema.verify(e)
    e2 = schema.add_step(e, "normalize", "x", "2026-10-30", "abc")
    assert schema.verify(e2)
    tampered = schema.Evidence(**{**e2.__dict__, "attributes": {"a": 2}})
    assert not schema.verify(tampered)


def test_hash_ignores_key_order():
    a = schema.make("t", "s", "cloud", "k", "x", "d", {"a": 1, "b": 2})
    b = schema.make("t", "s", "cloud", "k", "x", "d", {"b": 2, "a": 1})
    assert a.content_sha256 == b.content_sha256


@pytest.mark.parametrize("kw", [{"category": "nope"}, {"tenant_id": ""}])
def test_make_rejects(kw):
    args = {"tenant_id": "t", "source": "s", "category": "cloud", "kind": "k", "subject": "x", "observed_at": "d",
            "attributes": {}} | kw
    with pytest.raises(ValueError):
        schema.make(**args)


def test_connectors_measured(evidence):
    assert len(connectors.ALL) == 24
    assert len(evidence) == 153 and all(schema.verify(e) for e in evidence)
    assert all([s.step for s in e.lineage] == ["fetch", "normalize"] for e in evidence)


@pytest.mark.parametrize("cls", connectors.ALL, ids=lambda c: c.name)
def test_each_connector_offline_and_read_only(cls):
    c = cls("t1")
    assert c.collect()
    with pytest.raises(NetworkDisabled):
        c.call_api()
    for s in c.read_only_scopes:
        assert not any(w in s.lower() for w in ("write", "manage", "delete", "admin"))


def test_tenant_stamped():
    assert {e.tenant_id for e in connectors.EntraID("acme").collect()} == {"acme"}


# ---- webhooks ----
SECRET, OLD = b"s-new", b"s-old"
NOW = 1_793_000_000
MSG = {"id": "m1", "source": "nocode_zapier", "category": "webhook", "kind": "training", "subject": "u1",
       "observed_at": "2026-10-30", "attributes": {"course": "AT-02"}}


def _send(rx, body, secret=SECRET, ts=NOW, now=NOW, header=None):
    h = {webhooks.HEADER: header if header is not None else webhooks.sign(secret, body, ts)}
    return rx.handle(h, body, now)


def test_webhook_flow():
    rx = webhooks.WebhookReceiver("t1", [SECRET])
    body = json.dumps(MSG).encode()
    r = _send(rx, body)
    assert r.status == 202 and schema.verify(r.evidence)
    assert _send(rx, body).status == 409                      # same signature replayed
    assert _send(rx, body, ts=NOW + 1, now=NOW + 1).status == 200   # same id, new signature: idempotent


@pytest.mark.parametrize("case,status", [
    ("bad_secret", 401), ("old_ts", 401), ("no_header", 401), ("malformed", 400), ("too_big", 413),
    ("not_json", 400), ("bad_category", 422)])
def test_webhook_rejections(case, status):
    rx = webhooks.WebhookReceiver("t1", [SECRET], max_body=5000)
    body = json.dumps(MSG).encode()
    if case == "bad_secret":
        r = _send(rx, body, secret=b"wrong")
    elif case == "old_ts":
        r = _send(rx, body, ts=NOW - 301)
    elif case == "no_header":
        r = rx.handle({}, body, NOW)
    elif case == "malformed":
        r = _send(rx, body, header="garbage")
    elif case == "too_big":
        r = _send(rx, b"x" * 5001)
    elif case == "not_json":
        r = _send(rx, b"not json")
    else:
        r = _send(rx, json.dumps({**MSG, "category": "nope"}).encode())
    assert r.status == status


def test_secret_rotation():
    rx = webhooks.WebhookReceiver("t1", [SECRET, OLD])
    assert _send(rx, json.dumps(MSG).encode(), secret=OLD).status == 202
    rx2 = webhooks.WebhookReceiver("t1", [SECRET])
    assert _send(rx2, json.dumps(MSG).encode(), secret=OLD).status == 401


# ---- OpenAPI ----
@pytest.mark.parametrize("name", openapi.available_specs())
def test_openapi_specs_collect(name):
    c = openapi.OpenAPIConnector("t1", openapi.load_spec(name))
    ev = c.collect()
    assert ev and all(schema.verify(e) for e in ev)


@pytest.mark.parametrize("mutate,err", [
    (lambda s: s.update(openapi="2.0"), "3.x"),
    (lambda s: s.pop("x-arcampe"), "missing x-arcampe"),
    (lambda s: s["x-arcampe"].update(operationId="nope"), "not found"),
])
def test_openapi_validation(mutate, err):
    s = json.loads(json.dumps(openapi.load_spec(openapi.available_specs()[0])))
    mutate(s)
    assert any(err in e for e in openapi.validate_spec(s))


def test_openapi_rejects_write_operations():
    s = json.loads(json.dumps(openapi.load_spec(openapi.available_specs()[0])))
    op = s["x-arcampe"]["operationId"]
    for item in s["paths"].values():
        for m in list(item):
            if item[m].get("operationId") == op:
                item["post"] = item.pop(m)
    assert "only read-only GET operations are allowed" in openapi.validate_spec(s)


# ---- no-code ----
def test_nocode_payload_accepted_by_receiver():
    rx = webhooks.WebhookReceiver("t1", [SECRET])
    for i, rec in enumerate(nocode.RECIPES):
        p = nocode.recipe_payload(rec, {"id": f"z{i}", "subject": "x", "observed_at": "2026-10-30"})
        assert _send(rx, json.dumps(p).encode(), ts=NOW + i, now=NOW + i).status == 202


def test_nocode_export(tmp_path):
    assert nocode.export(tmp_path) == ["n8n_evidence_workflow.json", "zapier_style_recipes.json"]
    assert ".example" in nocode.ENDPOINT
    json.loads((tmp_path / "n8n_evidence_workflow.json").read_text())


# ---- mapper ----
def test_mapper_measured():
    r = mapper.evaluate()
    assert (r["items"], r["auto"], r["precision"], r["recall"]) == (60, 58, 0.983, 0.95)


def test_mapper_threshold_tradeoff():
    s = mapper.sweep()
    assert [x["threshold"] for x in s] == sorted(x["threshold"] for x in s)
    assert s[0]["auto"] >= s[-1]["auto"]


def test_mapper_low_confidence_goes_to_review():
    assert mapper.map_text("x", "lunch menu for friday").decision != "auto"
