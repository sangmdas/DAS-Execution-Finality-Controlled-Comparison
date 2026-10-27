# DAS Execution-Finality: A Falsifiable Five-Design Payment Security Comparison

**Runnable research demo • Python 3.10+ • Standard library only • Synthetic transactions • 96 automated tests • 65 scenario/implementation observations**

This repository tests one narrow, reproducible issue: **does the final effective payment operation still match the authorized payment when an attacker changes a command after upstream approval?** The motivating setting is a fictional accommodation booking on a Very Large Online Platform (VLOP), but this is **not a real hotel or payment system**.

> **Study result:** two deliberately weak conventional configurations and an intentionally misplaced sink let changed downstream operations through. A DAS-inspired sink-side checker stops them. **A strong conventional transactional resource-server model also stops them.** This is an honest, testable comparison of implementation designs, **not** evidence that DAS invented all transaction-integrity safeguards or that any actual vendor's product is vulnerable.

**Research foundation:** [Verifiable Marketplace Fraud Prevention and Execution-Finality Architecture — Zenodo](https://zenodo.org/records/23689735), particularly steps 17–20 (payment intent, payment Finality Sink, beneficiary change and outcome/retry), step 22 (revocation), and step 25 (testing). A different [larger Python/Go/JavaScript marketplace reference repository](https://github.com/sangmdas/DAS-Marketplace-Fraud-Prevention-AI-Security-Phishing-Protection-Execution-Finality) contains broader examples and 200 tests. **The 96 tests here are new, independent focused checks; do not add them to existing suites without addressing overlap and distinct code bases.**

## Executive demonstration

Run from the repository root:

```bash
python3 -m finality_lab.demo
```

Expected output:

```text
AUTHORIZED: booking-42, EUR 125.00, verified-hotel-merchant
EFFECTIVE:  booking-42, EUR 125.00, attacker-merchant

SESSION-ONLY                           ALLOW  fake-effects=1  SESSION_APPROVED_NO_EFFECT_CHECK
UPSTREAM-BOUND / UNCHECKED DISPATCH    ALLOW  fake-effects=1  UPSTREAM_CHECK_ONLY
SINK-VALIDATED                         DENY   fake-effects=0  ACTUAL_OPERATION_MISMATCH

Research mock: a successful event is only a list append, NOT a payment.
```

The `fake-effects` value counts objects appended to an in-memory `list`, **not bank transfers, API requests, network traffic or actual payments**. This example deliberately includes a compromised post-approval connector. A correctly configured resource server can prevent this too; the full attack matrix includes such a resource server.

## Five comparable designs

| Variant | What it does | Expected security behavior in the controlled experiment |
|---|---|---|
| `session_only` | Checks valid actor session, not final effect | Accepts unauthorized modifications and replay (intentionally) |
| `upstream_only` | Checks a digest of the initially approved instruction, then trusts downstream dispatch | Accepts post-check mutations (intentionally); NOT a complete OAuth RAR implementation |
| `candidate_checked_then_mutated` | Checks a signed candidate at a mistakenly placed 'sink', then permits unchecked later transformation | Rejects expired/revoked/replayed grants yet accepts post-check mutations (intentionally) |
| `native_atomic_resource` | Well-designed conventional resource server holds approved request and atomically checks final resource operation using local state | Rejects all modeled unauthorized effects **without** a separate cryptographic sink grant |
| `sink_guard` | Protected-authority simulator issues a signed scoped grant; effect boundary compares actual structured instruction, policy/revocation/expiry, then consumes authority under one lock | Rejects all modeled unauthorized effects, including replay and stale grants |

This comparison is **implementation-specific**. It does not assert that OAuth, RATS, OPA, Envoy or other standards are inherently defective. **Strong existing systems can achieve the tested property** when deployed with complete boundary coverage and transaction binding.

## Run the tests and generate attack evidence

Requirements: Python **3.10+**, no pip packages, no web access.

```bash
python3 -m unittest discover -s tests -v
python3 -m finality_lab.experiments
```

Single-command Unix/macOS:

```bash
sh scripts/run_all.sh
```

Windows PowerShell:

```powershell
py -3 -m finality_lab.demo
py -3 -m unittest discover -s tests -v
py -3 -m finality_lab.experiments
```

Expected on the tested runtime (Python 3.13): **96 unit tests, 0 test failures.** The test count includes dynamically constructed scenario cases and unique adversarial assertions. `reports/ATTACK_MATRIX.md` documents **65 observations** (13 scenarios × 5 designs); these observations overlap with unit tests and must **not** be added to the 96-test count as if independent tests.

The intentionally weak designs are supposed to be exploited. Therefore a passing assertion such as `self.assertTrue(weak.dispatch(...).allowed)` means the security experiment **demonstrated an expected vulnerability**, not that the weak design is secure.

### Attack matrix summary

| Category | Session-only | Upstream-only | Candidate-checked, later mutated | Native transactional | DAS-inspired sink |
|---|---|---|---|---|---|
| Valid exact transaction | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| Beneficiary changed after approval | ALLOW (bad) | ALLOW (bad) | ALLOW (bad) | DENY | DENY |
| Amount/currency/booking/actor/property/route/op-id changed | ALLOW (bad) | ALLOW (bad) | ALLOW (bad) | DENY | DENY |
| Revoked, policy changed or expired | ALLOW (bad) | ALLOW (bad) | DENY | DENY | DENY |
| Reused approval for another effect | ALLOW (bad) | ALLOW (bad) | DENY | DENY | DENY |

For exact per-scenario reasons and counts see [the generated attack matrix](reports/ATTACK_MATRIX.md).

## Source files and supporting research

```text
finality_lab/model.py              Five intentionally distinct implementations, no network calls
finality_lab/demo.py               Minimal beneficiary-substitution demonstration
finality_lab/experiments.py        Reproducible 13x5 cross-implementation attack matrix

tests/test_comparison.py           96 local unit tests, explicit successful-attack assertions
reports/TEST_RUN.txt              Saved executed unittest transcript
reports/ATTACK_MATRIX.md         Machine-generated readable results
reports/attack_matrix.csv        Machine-readable comparison results
reports/attack_matrix.json       Structured test observations
reports/ENVIRONMENT.md          Local execution details and reproducibility boundaries

docs/PRIOR_ART_COMPARISON.md      RFC 9396, RFC 9449, RFC 9334, Envoy, OPA, Zanzibar,
                                PostgreSQL serializable transactions and PSP idempotency
docs/SECURITY_REVIEW.md          Attacker model, incomplete sink exploits, limits and counterexamples
docs/INDEPENDENT_REPLICATION_PROTOCOL.md
                                Third-party red-team assignments, positive/negative evidence
                                and external-pipeline acceptance criteria
docs/NARROW_TESTABLE_CLAIMS.md  Eight experimentally falsifiable propositions;
                                cautious patent-claim sketch, not a novelty opinion

scripts/run_all.sh              Demo, tests, fresh report generation
.github/workflows/test.yml      GitHub Actions on Python 3.10/3.12/3.13
LICENSE                         Non-commercial source-available research license
```

## The deliberately important counterexample: strong conventional enforcement

The `native_atomic_resource` version rejects **the same 13 modeled attack scenarios** as the signed-grant sink version. It stores authorized transaction parameters and checks them at the resource's actual transaction boundary using one local lock and one-use ticket. It has **no distinct signed Finality Sink grant**.

This is not an endorsement of a specific commercial system. It shows that *correctly placed ordinary access control with transactional state can provide the modeled benefit*. Therefore the strongest defensible claim is the narrower architectural hypothesis: can a **separate protected authority plus independently observed sink and verifiable consequence-path coverage** offer added trust separation, interoperability or distributed assurance beyond an equivalently hardened resource server? **That has not yet been experimentally shown in this repository.**

## Known limitations: essential before public claims

1. One Python process; in-memory lock and fake list; no durable/remote atomic payment operation.
2. The `effective` instruction is supplied by the simulator; no independent capture at a real PSP/kernel/TEE boundary.
3. The fake rail can be called directly by code that holds its object: **non-bypassability is not proven**.
4. The signed grant is copyable and must **not** be called a fully non-bearer capability.
5. No actual RATS remote attestation, TEE/HSM isolation, OAuth 2.0 RAR token exchange, DPoP or real Envoy/OPA deployment.
6. No verified business/hotel/property identities, guest communications, payment settlement, real advertising rendering, or EU DSA compliance test.
7. No measured p95 production latency or platform-wide throughput; this is a focused logic demo, not a 25-step VLOP deployment benchmark.
8. No third-party independent review has been completed by publishing this repository alone.
9. Fake 'grant consumption on denial' can produce denial-of-service; deployable designs need authenticated submitters and retry/failure policies.
10. Real payment processors may have uncertain outcomes requiring reconciliation; this code does not simulate them.

A strong critic should review the [security gaps and attack opportunities](docs/SECURITY_REVIEW.md) rather than being asked to accept the model on faith.

## How to conduct a fair independent review

1. Reproduce the demo and machine-generated results with a pinned repository commit and Python version.
2. **Make the attack succeed** against the intentionally incomplete systems, recording the exact changed effective parameters.
3. Attempt to make the same attack succeed against `native_atomic_resource` and `sink_guard` without altering their trusted-code assumptions.
4. Explicitly attack those assumptions: exposed rail handle, post-check transformer, copied grant, process crash, multi-process race, alternative PSP endpoint and stale distributed revocation.
5. Implement an honest existing-stack comparator (RAR-authorized resource server + OPA/Envoy or native PSP idempotency) in a permitted staging environment, then try the same mutation schedule.
6. Publish the complete results, including failures, caveats, source versions and new mitigations. Do not claim independent validation until an unaffiliated reviewer actually performs it.

## Prior art, attribution, and patent disclosure discipline

See [source-grounded comparison](docs/PRIOR_ART_COMPARISON.md). The repo credits long-standing technologies, including OAuth RAR fine-grained payment authorization, DPoP key binding, RATS attestation, mature policy enforcers, transaction isolation and idempotency. The repo **does not** claim to invent those primitives.

Publication of this research code does not itself amend an as-filed PCT application; later implementations cannot repair original insufficiencies of disclosure. The [narrow testable-claims document](docs/NARROW_TESTABLE_CLAIMS.md) labels unproven elements, including independent effect observation, sink-local protected durable state and complete effect-path mediation. Determine as-filed support and patentability separately.

## License

Copyright (c) 2026 Sangam Kumar Das. Released under the included **source-available non-commercial research and evaluation license** (not OSI-approved). It permits non-production evaluation under the license terms and reserves patent rights. This is not an IETF standard, third-party vendor endorsement, certified marketplace safety product or legal compliance guarantee.

## Feedback invitation

Engineers and reviewers are invited to submit **minimal counterexamples**, prior disclosure references and patches that expose inaccuracies or missing trust boundaries. Especially valuable is evidence that a strong conventional baseline already provides the same property—which this repository explicitly acknowledges—or evidence of a differential under equivalent trust assumptions. The goal is falsifiable engineering, not a volume-of-publications contest.
