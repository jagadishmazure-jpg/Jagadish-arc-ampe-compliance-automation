"""Synthetic sign-in / activity stream with labelled attack scenarios (seeded, deterministic)."""
import datetime as dt
import json
import pathlib
import random

OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "platform"


def build(seed: int = 7) -> dict:
    rng = random.Random(seed)
    t0 = dt.datetime(2026, 10, 30, 0, 0)
    users = [f"user{i:03d}@lakehaven-hx.example" for i in range(1, 31)]
    ev = []

    def add(minute, user, kind, country="US", ok=True, scenario=None, **kw):
        ev.append({"at": (t0 + dt.timedelta(minutes=minute)).isoformat(), "user": user, "kind": kind,
                   "country": country, "ok": ok, "scenario": scenario, **kw})

    for _ in range(600):   # normal noise
        u = rng.choice(users)
        m = rng.randint(0, 1439)
        k = rng.choice(["signin", "signin", "signin", "download"])
        if k == "download":
            add(m, u, k, count=rng.randint(1, 40))
        else:
            add(m, u, k, ok=rng.random() > 0.03)
    for i in range(7):     # S1 brute force: 7 failures in 6 minutes
        add(300 + i, "user004@lakehaven-hx.example", "signin", ok=False, scenario="S1-bruteforce")
    add(400, "user009@lakehaven-hx.example", "signin", scenario="S2-travel")           # S2 impossible travel
    add(445, "user009@lakehaven-hx.example", "signin", country="RO", scenario="S2-travel")
    add(610, "user015@lakehaven-hx.example", "role_assignment", role="Global Administrator", via_pim=False,
        scenario="S3-privesc")
    add(700, "user021@lakehaven-hx.example", "download", count=1800, scenario="S4-exfil")
    add(800, "admin02@lakehaven-hx.example", "signin", country="NG", admin=True, scenario="S5-admin-abroad")
    add(900, "user022@lakehaven-hx.example", "role_assignment", role="Global Administrator", via_pim=True)  # benign
    ev.sort(key=lambda e: (e["at"], e["user"]))
    return {"note": "synthetic events; 'scenario' is the ground-truth label used only for scoring", "events": ev}


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "events.json").write_text(json.dumps(build(), indent=0) + "\n")
    print("wrote events.json")
