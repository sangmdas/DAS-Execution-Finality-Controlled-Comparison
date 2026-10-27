# Independent review and reproducibility protocol

**Objective:** Let an external engineer reproduce (A) intentional compromise of incomplete controls, (B) local refusal by two hardened alternatives, and (C) tests that may falsify the DAS-inspired implementation's additional security assumptions.

## Preparation

- Obtain a clean copy of the repository and record its SHA-256 hash/commit ID, Python runtime and operating system.
- Read `docs/SECURITY_REVIEW.md` and `docs/PRIOR_ART_COMPARISON.md` *before* interpreting passing results.
- Verify `python3 --version` >=3.10. No third-party dependency is needed to run the test suite.
- Run: `python3 -m finality_lab.demo`; `python3 -m unittest discover -s tests -v`; `python3 -m finality_lab.experiments`.
- Compare `reports/attack_matrix.csv` with fresh outputs. **Do not** count an intentional attack that succeeds against a weak comparator as a test-suite failure; its expected weakness is what is being demonstrated.

## Detailed adversarial assignments

| ID | Assignment | Expected acceptance criterion | Impact if falsified |
|---|---|---|---|
| P-01 | Change beneficiary after approval, preserving actor/booking | Weak designs mock-commit; protected/native refuse | Primary equality invariant |
| P-02 | Change amount, currency, booking, property, actor, route and op-id individually | Hardened designs reject each mismatched effective op | Descriptor coverage |
| P-03 | Reuse approved operation after one effect | No second mock effect under guard or native baseline | Replay invariant |
| P-04 | Reuse an authentic grant after a denied material mismatch | Guard must refuse even restored benign operation | Denial consumption |
| P-05 | Revoke or change policy after issuing grant | Guard/native deny stale approval | Execution-time freshness |
| P-06 | Submit malformed/tampered signatures and metadata | No effect; original unmodified grant remains separately verifiable | Signature scope |
| P-07 | 64 threads concurrently submit same grant | Exactly one local effect | Single-process atomicity |
| P-08 | Place an unverified effect-changing transformer *after* check | Intentionally incomplete sink is bypassed | Necessity of final-effect observation |
| P-09 | Bypass the Python guard and call fake rail directly | **Attack succeeds** in this mock; document as architectural limitation | No proven non-bypassability |
| P-10 | Read/copy the Python grant and replay with matching payload before legitimate client | First authenticated resource actor is **not established** by this mock | No proven non-bearer authority |
| P-11 | Kill process after fake side effect but before external acknowledgment (adapt to real PSP test sandbox) | The mock cannot establish durable reconciliation | Crash/indeterminate gap |
| P-12 | Replace `threading.Lock` with distributed replicas/processes | Single-process safety is insufficient for multi-process concurrency | Distributed atomicity gap |
| P-13 | Substitute a real OAuth 9396-aware resource server + native idempotency | Well-configured existing technology may achieve same protection | Patent/novelty counterexample |
| P-14 | Prove final effective payment parameters are independently observed at PSP boundary | Not demonstrated by passing a Python argument | Crucial observation proof |
| P-15 | Evaluate real payment-gateway alternate routes/refunds/queued jobs under permission | Requires authorized, sandboxed staging system; not covered by toy | Consequence-path completeness |

## Documentation for independent auditors

Record reviewer organization (if they consent), date, exact version hash, command transcript, observed/expected outcomes, technical limitations, newly discovered bypasses, environmental deviations, source patches, failed cases and remediation attempts. Capture artifacts without customer or payment secrets. Publish both successful and unsuccessful attacks; do not ask reviewers to endorse patents or use their employer's name without permission.

## Proposed next controlled integration

1. Build a resource-server implementation using existing RAR-like payment authorization details. Implement proper current resource-policy enforcement and idempotency. Do **not** intentionally weaken it.
2. Put a separate protected-authority validator and sink-local monitor next to a genuinely controlled payment sandbox API.
3. Use an authorized proxy/connector fault injector to change final beneficiary, operation identity, amount and route at every identified transformation point.
4. Add durable storage and multi-process races, crash/restart, uncertain PSP responses, delayed queues and revocation propagation.
5. Collect per-case traces, observed method/route, actor proof, effective operation digest, sink-local generation, consumption record, processor outcome, false positives, timeouts and p50/p95/p99 incremental latency.
6. Publish a *differential* only if one architecture demonstrably blocks an attack that an equivalently configured, strong conventional baseline does not; otherwise document functional equivalence and restrict claims.

## Ethical/legal boundaries

Use fictional identities, local simulators or payment-provider test modes; no probing real hotels, payment accounts, Booking.com, users, financial institutions or unaffiliated services without explicit written authorization and scope. No live money movements occur in this repository.
