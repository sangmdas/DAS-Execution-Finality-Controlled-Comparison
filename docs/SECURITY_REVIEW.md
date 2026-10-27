# Threat model, adversarial findings and admitted gaps

## System boundary

This code is a **pure Python in-memory educational comparison** about a payment instruction for a fictional accommodation booking. The attacker controls a transport/connector that can replace the final effective payment command after an upstream approval. The simulated protected authority and modeled sink code are outside that attacker-control region. The experiment never contacts a bank, hotel, payment processor, browser, AI agent or production service.

## Assets and trust boundaries

- **Assets:** approved beneficiary, amount in integer minor currency units, booking/property binding, actor, operation identity, route, current protected policy/revocation generation, expiration and single-use state.
- **Untrusted input:** upstream proposed candidate, mutable connector/queue output, replayed signed grant and request metadata.
- **Simulated trusted roles:** protected authority's HMAC key and policy; guarded sink's lock and state; fake ledger as effect-recorder.
- **Assumed but NOT proven:** actual sink obtains genuine effective operation parameters independently; the payment rail cannot be invoked by an alternative path; authenticated sink identity; grant cannot be copied/misused out of context; protected storage survives crashes; atomicity with a real PSP; system-wide revocation convergence.

## Threat scenarios exercised

1. Substitution of beneficiary after valid approval.
2. Amount inflation.
3. Currency substitution.
4. Substitution of booking reference, property and actor.
5. Operation-id substitution and an alternate route string.
6. Revocation *after* approval but before dispatch.
7. Policy generation change after approval.
8. Expiration before dispatch.
9. Replay of one approval after a successful dispatch.
10. Tampered signature, sink binding, and grant fields.
11. Previously denied authentic grant retried as a benign operation (must remain denied).
12. Concurrent use of the same approval across 64 in-process callers (exactly one local event).
13. A deliberately **misplaced sink** that verifies the approved candidate but permits a later unvalidated connector rewrite. This design *uses a signature* and single-use state yet still admits an attack.

These cases are recorded with expected decisions and executable results in `reports/ATTACK_MATRIX.md`, `reports/attack_matrix.csv` and `tests/test_comparison.py`.

## Where attacks succeed — intentionally

- `session_only`: an authenticated actor can issue a changed effective payment (8 mutation types) because there is no transaction-specific final check.
- `upstream_only`: a candidate-specific authorization digest passes, but the unchecked downstream command can be changed (8 mutation types). Stale authority and replay also succeed in this deliberately incomplete adapter.
- `candidate_checked_then_mutated`: *even a purported Finality Sink* can permit changed downstream consequences if its check precedes another effect-changing component. The eight mutation cases succeed despite the candidate signature being checked. Expiry, policy change and replay remain blocked here, demonstrating that replay protections alone are not sufficient for exact finality.
- `native_atomic_resource`: denies modeled violations through native exact-operation comparison, local state and transactional consumption. This shows the protected effect can be implemented by conventional systems.
- `sink_guard`: denies modeled violations with signed grant and final effective-parameter comparison.

## Attack the proposed model next: third-party reviewer checklist

**HIGH PRIORITY: these are known limitations, not solved by passing unit tests.**

### A. Direct effect-route bypass

The Python `FakeRail` is directly callable by anyone running Python with access to its instance. Calling its `_simulate_effect()` directly bypasses both the modeled sink and native resource-server checks. In Python, the leading underscore is merely a naming convention. **Thus these unit tests do not prove effect-path completeness or real non-bypassability.** Require OS/network isolation, protected PSP credentials, complete route inventory, enforced gateway-only credentials, and test every real payment-effecting API before claiming closure.

### B. Mutable effect after the apparent sink

If a downstream serializer, proxy, connector, queue consumer or bank adapter can rewrite the beneficiary *after* the last check, the system is vulnerable. `IncompleteCandidateCheckingSink` makes this attack explicit. A production design must measure the bytes/operation in the trust boundary where the effect is actually committed or establish a protected cryptographic binding reliably verified by the final actuator/processor.

### C. HMAC grant remains copyable

The toy `Grant` is a serializable, signed bearer-like artifact; it is **not cryptographically non-bearer**. Anyone who obtains the grant and can invoke the sink with a matching approved operation may attempt to cause the approved action. The local single-use set limits repeats but does not authenticate the invoker. A real non-bearer design requires authenticated or otherwise non-transferable context, a secret that never leaves the protected authority domain, attested channel or resource-native state binding, and a threat-model-specific proof.

### D. HMAC/private state is not hardware protected

The authority and sink coexist in one Python process. The key, in-memory state and mock rail could be introspected or modified by a process-level attacker. No TEE/HSM, remote attestation, mTLS, confidential computing, separate domain or kernel gate is actually implemented.

### E. Atomicity only covers a single Python process

`threading.Lock` serializes current local calls; it is not a crash-safe, interprocess, distributed or PSP transaction. A real external payment can commit before an acknowledgment arrives, leaving an indeterminate outcome. Require durable idempotency, same-transaction/processor guarantees, reconciliation, retry-state classification and crash-injection tests.

### F. Routing/policy coverage

Changing a string named `route` is not proof of route coverage. Need an inventory of effect-capable paths, indirect workers, queues, refunds, payout updates, support accounts, API aliases, retry systems and batch jobs, and enforcement tests with controls disabled/bypassed under authorization.

### G. Cross-domain evidence provenance

This toy obtains `effective` through an input argument from the test harness. It does **not** demonstrate independently acquiring the true effective command from a processor, NIC, kernel hook, or protected actuator. A successful product proof must inspect actual route-specific evidence.

### H. Denial consumes a grant and may cause deliberate denial-of-service

The guard burns authentic grants after a mismatch. If an attacker can cause invalid commands to be submitted with a victim's otherwise valid grant, it may deny subsequent legitimate use. Determine the accepted availability tradeoff, authenticated retry semantics, escalation policy, and durable records. This threat should be evaluated, not hidden.

### I. Hard-coded single actor and booking

This experiment includes one fictional hotel, one booking, one payee and one currency. It is not a Very Large Online Platform performance model. There is no multi-tenant RBAC/ABAC graph, multi-region consistency, fraud classifier, actual KYB check, real PSP, privacy compliance or interface measurement.

## Credible claim boundaries

- **Supported:** for the synthetic modeled path, real local unit tests show that an actual-operation checker with local single-use protected state denies selected post-approval mutations, and that deliberately incomplete designs do not.
- **Also supported:** an independent native transactional resource-server model offers the same synthetic denial property without a distinct signed grant.
- **Not supported:** original novelty; superior real-world security; avoidance of all design-arounds; production-scale throughput/latency; legal compliance; implementation of all PCT embodiments; actual multi-platform non-bypassable enforcement.
- **Independent security testing status:** no independent third-party results have been supplied. Current work is author-side adversarial tests intended to enable *future* independent replication.
