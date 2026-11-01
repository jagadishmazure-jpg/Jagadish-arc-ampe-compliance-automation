# Architecture overview (template)

System: Lakehaven eligibility and enrollment platform

1. Data flow diagram (connectors -> evidence store -> checks -> POA&M / SSPP / binder).
2. Trust boundaries (customer tenant, platform, Azure, Microsoft Foundry private endpoint).
3. Network: private endpoints, no public data-plane access, WAF in prevention mode.
4. Regions: U.S. only. List each region used.
5. Sub-processors and what each one can see.
6. Shared responsibility matrix (docs/shared_responsibility.csv).
