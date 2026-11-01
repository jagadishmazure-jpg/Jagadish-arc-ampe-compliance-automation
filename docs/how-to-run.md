# How to run

> **In one line:** the exact commands to install, test and run everything offline, plus the optional cloud steps.
>
> **Read this if:** you want to run it yourself.

## Offline (default)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python -m arcampe all --out out
```

## One command at a time

| Command | Output |
|---|---|
| `python -m arcampe catalog` | Family x label table |
| `python -m arcampe assess` | Finding counts by source |
| `python -m arcampe poam --out out` | `out/poam.csv` |
| `python -m arcampe sspp --out out` | `out/sspp.xlsx` |
| `python -m arcampe conmon --out out` | `out/conmon.md`, `out/conmon.html` |
| `python -m arcampe binder --out out` | `out/ato_binder.zip` |
| `python -m arcampe attest` | Attestation status and draft reminders |
| `python -m arcampe risk` | FAIR top 10 |
| `python -m arcampe trust` | T1-T8 results |
| `python -m arcampe integrations` / `mapper` / `schedule` / `audit` | Integration, mapper, scheduler and audit plan results |

## Regenerate synthetic data
```bash
for s in make_fixtures make_connector_fixtures make_attestations make_poam_history \
         make_platform_fixtures make_openapi_specs make_policies make_approvals; do python scripts/$s.py; done
```
All generators are seeded; CI fails if output changes.

## Docs
```bash
python scripts/render_docs.py          # refresh the output blocks
python scripts/render_docs.py --check  # CI
```

## IaC (optional, no Azure login, nothing deployed)
```bash
cd infra/terraform && terraform init -backend=false && terraform fmt -check && terraform validate && terraform test
tflint --init && tflint
az bicep build --file infra/bicep/main.bicep --stdout > /dev/null
```
Applying Terraform would create Azure Policy definitions and an assignment at subscription scope. Policy
definitions have no charge, but do not apply without the owner's approval.
