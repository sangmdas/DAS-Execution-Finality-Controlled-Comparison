# Narrow, technically falsifiable statements and candidate claim language

The term **claim** below means an experimental assertion or proposed implementation limitation. Nothing here determines patent eligibility, novelty, priority support, enforceability or freedom to operate. Before legal claim amendment, confirm the exact operative limitations are fully supported in the **original as-filed disclosure**, not merely later code or publications.

## Public-facing propositions supported by this experiment

### H1 — Post-approval payment-beneficiary change

**Statement:** In this controlled simulated workflow, the guarded design denies a payment whose effective beneficiary differs from that in the signed approved payment descriptor, even though the upstream actor and original candidate remain unchanged.

**Test:** `test_payment_substitution_rejected_at_guarded_sink`; `beneficiary_substitution` matrix; `docs/SECURITY_REVIEW.md`.

**Falsifier:** a supplied effective beneficiary differs, the signed grant is unchanged, yet the guarded mock rail logs an effect.

**Caveat:** a strongly implemented *ordinary* resource server also blocks the same case; this is not a DAS-exclusive invention claim.

### H2 — Candidate checking does not imply final-effect checking

**Statement:** The intentionally broken variant that checks the authentic signed candidate but allows an unchecked later connector to modify the effect admits beneficiary substitution.

**Test:** `test_incomplete_sink_can_pass_then_mutate_effect`.

**Falsifier:** the post-check transformer cannot change effective fields; or a truly final trusted sink validates the transformed object. This is a trust-boundary placement claim, not a new cryptographic primitive.

### H3 — Scope integrity across a material operation descriptor

**Statement:** The guarded simulator refuses single-field substitutions in actor, property, booking, amount, currency, payee, route and operation identity when compared with an approved operation.

**Test:** 8 mutation families in `AttackMatrixTests`; observed rows in `attack_matrix.csv`.

**Falsifier:** any controlled field changes while effect still appends to guarded fake rail.

### H4 — Freshness check at the sink

**Statement:** For this model, altering protected policy/revocation generation or allowing expiry between approval and dispatch makes the sink deny the originally approved operation.

**Test:** `TemporalAttacks`, `test_stale_policy_denied`, `test_revoked_grant_denied`, `test_expired_grant_denied`.

**Falsifier:** a prior-generation grant yields a new mock effect.

### H5 — Denial and consumption semantics

**Statement:** For this model, a signed grant that is presented with a materially mismatched effective operation cannot be reused for a later matching operation, and a successfully consumed grant cannot cause a second mock effect.

**Test:** `test_rejected_grant_burned_on_mismatch`, `test_valid_payment_allowed_once`.

**Falsifier:** two mock rail entries result from the same grant or a mismatched first attempt later succeeds. **Availability caveat:** attacker-triggered grant burning can cause denial of service.

### H6 — In-process concurrent single-use

**Statement:** With a single guarded process and one `threading.Lock`, 64 concurrent simulated dispatch attempts sharing one signed approval yield precisely one committed fake-rail event.

**Test:** `test_concurrent_single_use_64_callers`.

**Falsifier:** two or more fake-rail events from one grant. **Do not extend this to processes/regions/PSPs** without durable tests.

### H7 — A native transactional resource can match the modeled security property

**Statement:** A simulated conventional transactional resource server retaining the approved instruction and consuming a one-use ticket under a lock rejects every modeled attack rejected by the DAS-inspired sink. A separate cryptographic grant is not logically necessary to achieve this local property.

**Test:** `native_atomic_resource` rows; `test_strong_conventional_resource_rejects_substitution`.

**Falsifier:** a modeled scenario where the native resource admits an unauthorized effect while the sink guard refuses it under equivalent permissions/observation/trust assumptions. This is the most important counterexample to overbroad claims of exclusivity.

### H8 — Limits of the currently executable proof

**Statement:** The experiment does *not* establish non-bearer capability, hardware isolation, independent PSP-derived observation, full path closure, cross-region revocation, legal compliance or production latency.

**Test:** architecture review, penetration review of Python object references, red-team checklist P-09 to P-15.

**Falsifier:** provide and independently reproduce a hardened deployment proving these properties under an explicit threat model. The present repo contains no such proof.

## Illustrative narrow system/implementation claim sketch (not a patent opinion)

> A computer-implemented test method, comprising: storing an approval of a first structured payment instruction identifying at least a booking, beneficiary, amount and operation identity; subsequently presenting a second structured payment instruction for simulated execution; at an effect-enforcement component obtaining a representation of the second instruction independently from the prior approved representation; comparing material fields of the two instructions; consulting a current revocation generation; and conditionally recording a single authorized mock effect only when the fields and revocation generation agree, with rejection for a mismatch.

**Already known in substance? Potentially yes.** Exact operation matching, current authorization and transactional consumption are found in conventional designs. This sketch **must not** be publicly represented as an established novel independent patent claim. It states only the tested computational behavior.

## Candidate *additional* differential to investigate, not yet demonstrated

> An enforcement arrangement in which an authority component independently issues context-scoped validation evidence, an effect-enforcement component obtains protected actual-operation observations unavailable for substitution by a requesting workload, consumption is made durable in protected sink-local state, and all identified alternative effect routes are unable to commit without the same validation condition.

The current simulator supports **only some logical checks** in this sentence. It does not substantiate genuine independent observation, protected-domain separation, non-bearer properties, durable sink-local state, or complete route coverage. Treat this as an experimental research hypothesis pending external implementation and as-filed priority examination.

## Suggested public technical wording

> “In a controlled Python simulation, intentionally incomplete session- and upstream-only authorization paths accepted 24 unauthorized payment operations across modeled attack categories. A deliberately misplaced signed candidate-check sink admitted eight more post-check mutations. A DAS-inspired effect-boundary verifier rejected the modeled attacks using an exact-operation comparison and local single-use state. Importantly, a well-configured conventional transactional resource-server model rejected the same attacks. The open research question is whether independently protected authority/effect separation and verifiable path completeness provide a further demonstrable advantage in distributed real-world deployments.”

**Never say:** “This proves DAS is the only system capable of preventing fraud,” “This is patent novelty verification,” “This is independently audited,” “All 25 marketplace stages were production validated,” or “No existing framework can do this.”
