# Source-grounded prior-art and engineering-baseline comparison

**Date prepared: 27 October 2026. Scope: engineering references, standards and published implementations, not an exhaustive patent novelty/obviousness search.** This report does *not* establish a legal priority date, a patent claim's validity, infringement, or distinctiveness over every prior disclosure. For a patent opinion, identify exact granted/pending claim limitations and review historical patent publications and source versions as filed.

## 1. The precise question this repository tests

A payment for `booking-42`, EUR 125.00, to `verified-hotel-merchant` receives upstream approval. An attacker can mutate the **effective downstream command** to `attacker-merchant` while preserving the authorized candidate, session, and upstream ticket. Does the configured *final controlled effect path* check the real downstream instruction, freshness, scope and protected usage state, or trust the earlier decision?

**Finding of this synthetic experiment:** deliberately weak configurations admit the attack; both (i) a proposed independently issued signed grant verified at a modeled Finality Sink and (ii) a conventional, strongly implemented transactional resource server reject the attack. This result demonstrates a deployment/control-property gap, **not** exclusivity or novelty of the DAS concept.

**Five comparators (do not equate any one with the complete OAuth/RATS/Envoy specification):**

1. `session_only`: intentionally defective coarse session validation at an upstream boundary.
2. `upstream_only`: an exact operation digest is approved and checked **before** a subsequent malicious transform, but not checked again at the actual effect path.
3. `candidate_checked_then_mutated`: a purported sink verifies the candidate and signed grant, but an unchecked connector **after** its check changes the resulting operation. This is deliberately incomplete even though it uses a signature, revocation and single-use state.
4. `native_atomic_resource`: a **strong existing-style design** that retains approved values inside the resource server, independently reads the current effective operation and atomically validates, consumes and commits. It does not need a distinct signed Finality Sink grant. This is a counterexample to the idea that only DAS terminology or cryptography can enforce the security property.
5. `sink_guard`: DAS-inspired protected-authority simulation, with operation-specific signed evidence, independent final descriptor comparison and local lock-protected consume-and-mock-effect.

## 2. Real baseline mechanisms; what they already do; remaining deployment questions

### RFC 9396 — OAuth 2.0 Rich Authorization Requests (RAR), May 2023

**Source:** https://www.rfc-editor.org/rfc/rfc9396.html

**Already established:** fine-grained JSON `authorization_details`; explicit payment initiation amount, currency, payee/creditor-account fields; resource-server availability of authorization details for enforcement (section 9); audience/location scoping; integrity considerations. RFC 9396 is particularly strong prior art against simplistic assertions that transaction-specific payment authorization or detailed payee binding was invented by DAS.

**Narrow issue to test:** a resource server that receives and **actually enforces** RAR authorization details can reject payment substitution. This repo's `upstream_only` does not do that downstream enforcement; it represents a *deficient integration*, not RFC 9396. RAR does not by itself specify this repo's separate signed sink artifact, end-to-end physical last-effect observer, or distributed operation-path-completeness proof. Those remain implementation-dependent questions, not necessarily unsolved problems.

**Falsifier:** implement RAR resource-side matching plus native transaction/revocation and show the same outcome. The `native_atomic_resource` comparator already illustrates functional equivalence for these synthetic threats.

### RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP), September 2023

**Source:** https://www.rfc-editor.org/rfc/rfc9449.html — especially section 11.7.

**Already established:** proof-of-possession keys, request URI/method constraints, token-to-key binding and replay countermeasures. **Critically**, RFC 9449 itself notes that DPoP alone does not cover the HTTP payload or general request headers. Combining DPoP with RAR resource checks, validation of body details, TLS integrity and appropriate PSP protections may stop the proposed attack.

**Narrow distinction:** DPoP by itself is not an assertion that the beneficiary in a changed payment payload is authorized. Nor does the DAS demo implement DPoP or prove superiority over a combined OAuth stack. Compare equivalent fully deployed controls, not acronyms.

### RFC 9334 — RATS Architecture (Remote ATtestation procedureS), January 2023

**Source:** https://www.rfc-editor.org/rfc/rfc9334.html

**Already established:** attestation Evidence, Verifier appraisal, Attestation Results, Relying Parties, freshness and trust-topology models. DAS may employ those pieces, but it does not own remote attestation. RATS alone is not a specification for exactly matching a pending payment at the payment processor. A relying party may apply additional policy; actual outcome depends on its enforcement implementation. The Python mock **does not implement attestation**.

### Envoy `ext_authz` and Open Policy Agent (OPA)

**Sources:**
- https://www.envoyproxy.io/docs/envoy/v1.40.1/configuration/http/http_filters/ext_authz_filter
- https://www.openpolicyagent.org/docs/envoy
- https://www.openpolicyagent.org/docs/envoy/tutorial-standalone-envoy

**Already established:** external, fine-grained request/context authorization at an enforcement proxy; configurable request-body and policy evaluation; deny-before-forward capabilities; sidecar policy decisions. A policy can compare transaction attributes and reject substitution at the actual message boundary. Envoy documentation identifies specific concerns about per-route authorization being bypassed by subsequent route-cache changes; this is relevant to alternate-path or post-check transformations but is not evidence that all deployments are vulnerable. An accurately positioned and complete Envoy/OPA control may provide the protection without a separately named DAS mechanism.

**Narrow issue to test:** actual post-check transforms, effective routing, bypass paths, credential swapping and the precise atomic relationship of a decision to a downstream irreversible effect. This repo does not run actual Envoy/OPA; that integration is future work.

### Zanzibar — Google’s Consistent, Global Authorization System (2019)

**Source:** https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/

**Already established:** large-scale external-consistency-aware authorization, sophisticated ACL models, causal ordering and highly available authorization checks. Consequently, general claims of cross-service authorization, high-scale policy decisions or revocation awareness cannot be attributed exclusively to a DAS concept. Distinguish the actual downstream transaction state and effect commit from authorization service consistency; integration is what matters.

### PostgreSQL / ACID / serializable resource transactions

**Source:** https://www.postgresql.org/docs/16/transaction-iso.html

**Already established:** serializable transaction guarantees, constraint checks and safe concurrency patterns. If a complete authorization predicate and the effect are in the same native database transaction, the system can implement actual-state verification and one-use consumption without separate signed grants. The `native_atomic_resource` comparator models this kind of native enforcement using a Python lock, not a real serializable database.

**Key limitation:** a local database transaction is not automatically atomic with an external bank rail or a queue; cross-service effects require processor-defined idempotency, outbox/inbox patterns, durable outcome reconciliation or distributed protocols with stated failure assumptions.

### Stripe API idempotency (published established payment-practice example)

**Sources:**
- https://docs.stripe.com/api/idempotent_requests
- https://stripe.com/blog/idempotency

**Already established:** an idempotency key can protect certain mutating API calls from duplicate retries, and matching parameters can be checked against the first request. This is substantial existing technology in replay, retries and consequence stability. It does not automatically authorize the beneficiary or guarantee a pre-processor approval still matches a changed payment; appropriate application controls remain required.

### Prior work in capability systems, authorization tokens, signed requests and reference monitors

Capabilities, message authentication codes, transaction-specific authorization, reference monitors, single-use tokens, policy generation numbers and access-control enforcement are all established design families. The words **protected**, **atomic**, **cryptographic**, **non-bearer**, **fail-closed** and **sink** are not enough, individually, to establish patent novelty. Narrow innovation questions require the actual claimed ordering, topology and concrete evidence that the specific whole was not known or obvious at the claimed priority date.

## 3. Mechanism comparison — no feature should be attributed exclusively without a claim chart

| Control/property | Known engineering baseline | Modeled DAS-style implementation | What is established by this repository? |
|---|---|---|---|
| Payee/amount-specific authorization | RFC 9396 + resource policy; transaction-specific signed intent | Signed operation-digest evidence | Both may bind payee/amount; not shown novel |
| Sender/token binding | DPoP / mTLS / token introspection | Toy HMAC signature on grant | Cryptographic signature *check* is demonstrated; actual sender constraint is **not** implemented |
| Independent effective-parameter check | Resource server / proxy / PSP validates actual request | Finality Sink compares actual descriptor | Both strong comparators reject substitutions |
| Transactional single-use | Database uniqueness/locks, idempotency, native commit | Local protected-set-and-lock simulation | One success under 64 in-process threads; **not** distributed atomicity |
| Revocation/freshness | Policy DB, token lifetime/introspection, Zanzibar consistency, generation counters | Signed revocation/policy generation and expiry | Old grants rejected in the toy model |
| Physical non-bypassability | Reference monitor / kernel/hypervisor / network isolation | Finality Sink ideally mediates all effect routes | **Not implemented or proven**; simulated alternate route only |
| Attestation | RFC 9334 and hardware vendors | Could feed protected state into decisions | **No TEE/HSM or attestation proof exists** in this repo |
| End-to-end processor outcome | PSP idempotency, reconciliation, receipts | Desired finality/outcome accounting | **Not implemented** beyond local fake rail |
| Client rendering and transparency | UI validation/advertising systems | Separate marketplace proposal | **Out of scope** of this narrow payment comparison |

## 4. The strongest prior-art objection to address

A well-designed resource server using RFC 9396 payment authorization details, transactional idempotency, current revocation checks, non-bypassable ingress policy and an actual-final-request validator may be **functionally equivalent in the modeled scenario** to the proposed Finality Sink. This repository *shows* that possibility through `native_atomic_resource`. The appropriate next research question is not “can only DAS stop the attack?” but whether a **particular independently sourced validation/evidence arrangement, distinct sink-bound authority and complete consequence-route mechanism** offers a further measurable property, interoperability advantage, or precisely claimable architecture over such systems.

## 5. What would count as a stronger novelty/enablement study?

- Produce a **dated** claim-to-feature chart for the exact PCT claim, paragraph, figure and as-filed support.
- Compare with RFC 9396 sections 2/9/12; RFC 9449 sections 4/11; relevant pre-priority OAuth payment profiles; transaction processing patents; capability security research; and relevant prior reference-monitor and transaction-integrity patents.
- Obtain real response bodies, routing tables, guard code paths and controlled effects from Envoy/OPA, native database or payment sandbox integration. No tests on third-party production platforms without authorization.
- Demonstrate a *differential*: one strong comparator with every known check correctly integrated still fails a particular attack that the claimed design blocks. If none is found, limit claims to the concrete architecture/integration or interoperability properties actually differentiated.
- Have an independent reviewer reproduce tests, review source, suggest adversarial mutations and disclose both successes **and failures**.

**This document is a preliminary comparison of selected public technology references, not a comprehensive patentability opinion.**
