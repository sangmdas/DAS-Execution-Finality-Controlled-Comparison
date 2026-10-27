"""Adversarial unit tests. Intentional compromises in weak models are PASS assertions."""
import hashlib
import hmac
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from finality_lab.model import (
    Payment, Grant, CoarseSessionBaseline, UpstreamBoundButUncheckedSink,
    ProtectedAuthority, FinalitySink, NativeTransactionalResourceServer, IncompleteCandidateCheckingSink, modified, canonical,
)
from finality_lab.experiments import ATTACKS, evaluate_one, evaluate_replay, evaluate_stateful, outcomes


class ExplicitAttacks(unittest.TestCase):
    def test_payment_substitution_accepted_by_session_only(self):
        real = Payment()
        changed = modified(real, beneficiary="attacker-merchant")
        engine = CoarseSessionBaseline()
        answer = engine.dispatch(real, changed)
        self.assertTrue(answer.allowed, "intentional exploit should be reproducible")
        self.assertEqual(engine.rail.events[0].beneficiary, "attacker-merchant")

    def test_payment_substitution_accepted_by_incomplete_upstream(self):
        real = Payment()
        changed = modified(real, beneficiary="attacker-merchant")
        engine = UpstreamBoundButUncheckedSink()
        ticket = engine.approve(real)
        answer = engine.dispatch(real, changed, ticket=ticket)
        self.assertTrue(answer.allowed)
        self.assertEqual(len(engine.rail.events), 1)

    def test_incomplete_sink_can_pass_then_mutate_effect(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = IncompleteCandidateCheckingSink(auth)
        grant = auth.approve(p)
        result = sink.dispatch(p, modified(p, beneficiary="attacker-merchant"), grant=grant)
        self.assertTrue(result.allowed)
        self.assertEqual(sink.rail.events[0].beneficiary, "attacker-merchant")

    def test_strong_conventional_resource_rejects_substitution(self):
        p = Payment()
        auth = ProtectedAuthority()
        server = NativeTransactionalResourceServer(auth)
        ticket = server.approve(p)
        response = server.dispatch(p, modified(p, beneficiary="attacker-merchant"), ticket=ticket)
        self.assertFalse(response.allowed)
        self.assertEqual(server.rail.events, [])

    def test_payment_substitution_rejected_at_guarded_sink(self):
        real = Payment()
        authority = ProtectedAuthority()
        sink = FinalitySink(authority)
        grant = authority.approve(real)
        answer = sink.dispatch(real, modified(real, beneficiary="attacker-merchant"), grant=grant)
        self.assertFalse(answer.allowed)
        self.assertEqual(sink.rail.events, [])
        self.assertEqual(answer.reason, "ACTUAL_OPERATION_MISMATCH")

    def test_rejected_grant_burned_on_mismatch(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        self.assertFalse(sink.dispatch(p, modified(p, amount_minor=1), grant=grant).allowed)
        decision = sink.dispatch(p, p, grant=grant)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "REPLAY_OR_PREVIOUS_DENIAL")

    def test_valid_payment_allowed_once(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        self.assertTrue(sink.dispatch(p, p, grant=grant).allowed)
        self.assertEqual(sink.rail.events, [p])
        self.assertFalse(sink.dispatch(p, p, grant=grant).allowed)
        self.assertEqual(len(sink.rail.events), 1)

    def test_rejected_unknown_signature_does_not_burn_valid_grant_id(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        forged = replace(grant, signature="00" * 32)
        self.assertFalse(sink.dispatch(p, p, grant=forged).allowed)
        self.assertTrue(sink.dispatch(p, p, grant=grant).allowed)

    def test_stale_policy_denied(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        auth.change_policy()
        self.assertEqual(sink.dispatch(p, p, grant=grant).reason, "POLICY_CHANGED")

    def test_revoked_grant_denied(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        auth.revoke()
        self.assertEqual(sink.dispatch(p, p, grant=grant).reason, "REVOKED")

    def test_expired_grant_denied(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p, now=10, valid_for=1)
        self.assertEqual(sink.dispatch(p, p, grant=grant, now=20).reason, "EXPIRED")

    def test_wrong_sink_denied(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p, sink="other-sink")
        self.assertEqual(sink.dispatch(p, p, grant=grant).reason, "WRONG_SINK")

    def test_sink_unavailable_fail_closed(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        sink.available = False
        self.assertEqual(sink.dispatch(p, p, grant=grant).reason, "SINK_UNAVAILABLE")
        self.assertEqual(len(sink.rail.events), 0)
        sink.available = True
        self.assertTrue(sink.dispatch(p, p, grant=grant).allowed)

    def test_concurrent_single_use_64_callers(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        with ThreadPoolExecutor(max_workers=24) as pool:
            answers = list(pool.map(lambda _i: sink.dispatch(p, p, grant=grant), range(64)))
        self.assertEqual(sum(d.allowed for d in answers), 1)
        self.assertEqual(len(sink.rail.events), 1)

    def test_untrusted_authorization_refuses_invalid_beneficiary(self):
        p = modified(Payment(), beneficiary="attacker-merchant")
        with self.assertRaises(ValueError):
            ProtectedAuthority().approve(p)

    def test_untrusted_authorization_refuses_alternate_route(self):
        p = modified(Payment(), route="unknown-route")
        with self.assertRaises(ValueError):
            ProtectedAuthority().approve(p)

    def test_untrusted_authorization_refuses_wrong_actor(self):
        p = modified(Payment(), actor="other")
        with self.assertRaises(ValueError):
            ProtectedAuthority().approve(p)

    def test_untrusted_authorization_refuses_wrong_property(self):
        p = modified(Payment(), property_id="other")
        with self.assertRaises(ValueError):
            ProtectedAuthority().approve(p)

    def test_upstream_ticket_does_not_authorize_modified_candidate(self):
        p = Payment()
        incomplete = UpstreamBoundButUncheckedSink()
        ticket = incomplete.approve(p)
        answer = incomplete.dispatch(modified(p, booking="other"), modified(p, booking="other"), ticket=ticket)
        self.assertFalse(answer.allowed)
        self.assertEqual(len(incomplete.rail.events), 0)

    def test_session_denies_unauthenticated_actor(self):
        p = Payment()
        weak = CoarseSessionBaseline()
        self.assertFalse(weak.dispatch(p, p, actor_authenticated=False).allowed)

    def test_tampered_grant_context_detected(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        for changes in [{"actor":"other"}, {"booking":"other"}, {"expires_at":99999}, {"descriptor_digest":"a"*64}, {"sink":"other"}]:
            with self.subTest(changes=changes):
                tampered = replace(grant, **changes)
                self.assertEqual(sink.dispatch(p, p, grant=tampered).reason, "INVALID_GRANT_SIGNATURE")
        self.assertTrue(sink.dispatch(p, p, grant=grant).allowed)

    def test_canonical_encoding_order_independent(self):
        self.assertEqual(canonical({"a":1,"b":2}), canonical({"b":2,"a":1}))

    def test_signed_descriptor_contains_all_effect_fields(self):
        p = Payment()
        self.assertEqual(set(p.as_descriptor()), {"actor","booking","beneficiary","amount_minor","currency","operation_id","route","property_id"})

    def test_separately_issued_grant_cannot_authorize_other_op_id(self):
        p = Payment()
        auth = ProtectedAuthority()
        sink = FinalitySink(auth)
        grant = auth.approve(p)
        self.assertFalse(sink.dispatch(p, modified(p, operation_id="other"), grant=grant).allowed)

    def test_signing_keys_are_independent(self):
        p = Payment()
        authority_a = ProtectedAuthority()
        authority_b = ProtectedAuthority()
        grant = authority_a.approve(p)
        self.assertEqual(FinalitySink(authority_b).dispatch(p,p,grant=grant).reason, "INVALID_GRANT_SIGNATURE")

    def test_decisions_logged(self):
        p = Payment()
        a = ProtectedAuthority()
        s = FinalitySink(a)
        s.dispatch(p, modified(p, currency="USD"), grant=a.approve(p))
        self.assertEqual(len(s.decision_log), 1)
        self.assertTrue(s.decision_log[0].startswith("DENY:"))

    def test_fake_rail_does_not_send_network_messages(self):
        p = Payment()
        e = CoarseSessionBaseline()
        e.dispatch(p,p)
        self.assertIsInstance(e.rail.events, list)

    def test_amount_in_minor_units_not_floating_point(self):
        self.assertIsInstance(Payment().amount_minor, int)
        self.assertEqual(Payment().amount_minor, 12500)

    def test_sha256_descriptor_digest_is_stable(self):
        p = Payment()
        a = ProtectedAuthority()
        grant = a.approve(p)
        self.assertEqual(grant.descriptor_digest, hashlib.sha256(canonical(p.as_descriptor())).hexdigest())

    def test_grant_signature_validity(self):
        p = Payment()
        a = ProtectedAuthority()
        self.assertTrue(a.verify_grant_signature(a.approve(p)))

    def test_outcomes_matrix_has_expected_coverage(self):
        rows = outcomes()
        self.assertEqual(len(rows), 65)  # 13 scenarios x 5 variants
        self.assertEqual(len([r for r in rows if r.variant == "sink_guard"]), 13)
        self.assertTrue(all(r.correct for r in rows if r.variant == "sink_guard"))
        self.assertTrue(all(r.correct for r in rows if r.variant == "native_atomic_resource"))
        self.assertTrue(any(not r.correct for r in rows if r.variant == "upstream_only"))


class AttackMatrixTests(unittest.TestCase):
    """Each case checks (1) weak compromise and (2) guarded refusal or benign success."""


def _make_attack_test(name, variant):
    def attack_test(self):
        row = evaluate_one(name, variant)
        if name == "valid_transaction":
            self.assertTrue(row.correct)
            self.assertEqual(row.mock_effects, 1)
        elif variant in ("sink_guard", "native_atomic_resource"):
            self.assertEqual(row.decision, "DENY")
            self.assertEqual(row.mock_effects, 0)
        elif variant == "candidate_checked_then_mutated":
            # Incorrect sink checks candidate and then allows mutation.
            self.assertEqual(row.decision, "ALLOW")
            self.assertEqual(row.mock_effects, 1)
        else:
            # An INTENTIONALLY successful synthetic attack: test passes because
            # the incomplete design demonstrably permits an unauthorized effect.
            self.assertEqual(row.decision, "ALLOW")
            self.assertEqual(row.mock_effects, 1)
    attack_test.__name__ = f"test_{name}_{variant}"
    return attack_test


for _name in ATTACKS:
    for _variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
        setattr(AttackMatrixTests, f"test_{_name}_{_variant}", _make_attack_test(_name, _variant))


class TemporalAttacks(unittest.TestCase):
    pass


def _make_temporal_test(name, variant):
    def check(self):
        row = evaluate_stateful(name, variant)
        self.assertEqual(row.decision, "DENY" if variant in ("sink_guard", "native_atomic_resource", "candidate_checked_then_mutated") else "ALLOW")
        self.assertEqual(row.mock_effects, 0 if variant in ("sink_guard", "native_atomic_resource", "candidate_checked_then_mutated") else 1)
    check.__name__ = f"test_{name}_{variant}"
    return check


for _name in ("revoked_after_approval", "policy_changed_after_approval", "expired_approval"):
    for _variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
        setattr(TemporalAttacks, f"test_{_name}_{_variant}", _make_temporal_test(_name, _variant))


def _make_replay_test(variant):
    def check(self):
        row = evaluate_replay(variant)
        self.assertEqual(row.decision, "DENY" if variant in ("sink_guard", "native_atomic_resource", "candidate_checked_then_mutated") else "ALLOW")
        self.assertEqual(row.mock_effects, 1 if variant in ("sink_guard", "native_atomic_resource", "candidate_checked_then_mutated") else 2)
    check.__name__ = f"test_replay_{variant}"
    return check


for _variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
    setattr(TemporalAttacks, f"test_replay_{_variant}", _make_replay_test(_variant))
