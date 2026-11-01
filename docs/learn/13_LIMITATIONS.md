# 13. Limitations

**What you'll learn:** what this repo is not, so nobody over-reads it.

**Read this after:** [12_RESULTS](12_RESULTS.md)

- **Synthetic only.** No real organisation, estate, people or vendors. No live API calls.
- **Not a certification.** Nothing here is an ATO, SOC 2 report, ISO certificate or FedRAMP authorization.
- **Crosswalks are approximate.** 30 of 34 framework mappings are author-built at control-family level and need an
  expert before real use. Readiness for those frameworks is an estimate.
- **AI agents are simple.** The evidence mapper is a deterministic keyword model, which is why replay works. A
  real LLM would need recorded seeds, temperature 0 and stored outputs to replay.
- **Simulated pieces.** Workflow actions, questionnaire sends, trust-to-revenue and AI ROI are simulated.
- **Reports never send** unless you add a transport, a config and an approval flag yourself.
- **Industry packs and multi-org** use approximate mappings; the four extra organisations have hash-generated
  synthetic results, not a real assessment.
- **Scanner import** reads one synthetic export format; real scanner exports vary and need field mapping.
- **Survey context** (in [07](07_AI_GOVERNANCE.md)) is the publisher's self-reported claims, not verified.

---

**Next:** [14_GRC_OPERATIONS](14_GRC_OPERATIONS.md)
