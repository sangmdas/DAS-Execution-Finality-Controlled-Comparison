"""Three deliberately scoped payment authorization designs for comparison.

WARNING: Entirely local, synthetic simulator. HMACs and Python objects here are
teaching aids, NOT a remote attestation, non-bearer capability, TEE/HSM, secure
network gateway, payment system, or proof that a real platform has closed all paths.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, replace
from decimal import Decimal
import hashlib
import hmac
import json
import secrets
import threading
from typing import Optional


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True)
class Payment:
    actor: str = "hotel-17"
    booking: str = "booking-42"
    beneficiary: str = "verified-hotel-merchant"
    amount_minor: int = 12500
    currency: str = "EUR"
    operation_id: str = "op-001"
    route: str = "platform-payment-rail"
    property_id: str = "property-17"

    def as_descriptor(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Grant:
    grant_id: str
    descriptor_digest: str
    actor: str
    booking: str
    property_id: str
    sink: str
    policy_generation: int
    revocation_generation: int
    expires_at: int
    signature: str

    def body(self) -> dict:
        data = asdict(self)
        del data["signature"]
        return data


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    event_count: int


class FakeRail:
    """No external I/O. Log is *not* an actual bank transfer."""
    def __init__(self):
        self.events: list[Payment] = []

    def _simulate_effect(self, operation: Payment) -> None:
        self.events.append(operation)


class CoarseSessionBaseline:
    """Intentionally weak deployment: validates only known login/session actor."""
    def __init__(self):
        self.rail = FakeRail()

    def dispatch(self, candidate: Payment, effective: Payment, *, actor_authenticated=True, **kwargs) -> Decision:
        if not actor_authenticated or candidate.actor != "hotel-17":
            return Decision(False, "SESSION_DENIED", len(self.rail.events))
        self.rail._simulate_effect(effective)
        return Decision(True, "SESSION_APPROVED_NO_EFFECT_CHECK", len(self.rail.events))


class UpstreamBoundButUncheckedSink:
    """Intentionally incomplete: exact approval IS checked before downstream mutation.

    This is NOT RFC 9396 as a whole; an RFC 9396-aware resource server can check
    payment details at processing time. This is a modeled misdeployment where
    dispatch later trusts the upstream result without reconstructing the effect.
    """
    def __init__(self):
        self.rail = FakeRail()
        self._approved_digests: set[str] = set()

    def approve(self, candidate: Payment) -> str:
        digest = hashlib.sha256(canonical(candidate.as_descriptor())).hexdigest()
        self._approved_digests.add(digest)
        return digest

    def dispatch(self, candidate: Payment, effective: Payment, *, ticket: Optional[str] = None, **kwargs) -> Decision:
        ticket = ticket or self.approve(candidate)
        # Checks the ORIGINAL candidate, but NOT the effective downstream bytes/state.
        if ticket not in self._approved_digests:
            return Decision(False, "UPSTREAM_TICKET_UNKNOWN", len(self.rail.events))
        if ticket != hashlib.sha256(canonical(candidate.as_descriptor())).hexdigest():
            return Decision(False, "UPSTREAM_CANDIDATE_MISMATCH", len(self.rail.events))
        self.rail._simulate_effect(effective)
        return Decision(True, "UPSTREAM_CHECK_ONLY", len(self.rail.events))


class ProtectedAuthority:
    """Toy protected policy state and operation-bound authorization issuance."""
    def __init__(self, *, key: Optional[bytes] = None):
        self._key = key or secrets.token_bytes(32)
        self.policy_generation = 1
        self.revocation_generation = 1
        self.expected_beneficiary = "verified-hotel-merchant"
        self.expected_actor = "hotel-17"
        self.expected_booking = "booking-42"
        self.expected_property = "property-17"
        self.allowed_route = "platform-payment-rail"

    def _signature(self, grant_body: dict) -> str:
        return hmac.new(self._key, canonical(grant_body), hashlib.sha256).hexdigest()

    def verify_grant_signature(self, grant: Grant) -> bool:
        return hmac.compare_digest(self._signature(grant.body()), grant.signature)

    def approve(self, payment: Payment, *, now: int = 1000, valid_for: int = 120, sink: str = "payment-sink-A") -> Grant:
        if not self._allowed_payment(payment):
            raise ValueError("protected authorization denied at issuance")
        data = {
            "grant_id": secrets.token_hex(12),
            "descriptor_digest": hashlib.sha256(canonical(payment.as_descriptor())).hexdigest(),
            "actor": payment.actor,
            "booking": payment.booking,
            "property_id": payment.property_id,
            "sink": sink,
            "policy_generation": self.policy_generation,
            "revocation_generation": self.revocation_generation,
            "expires_at": now + valid_for,
        }
        return Grant(**data, signature=self._signature(data))

    def _allowed_payment(self, payment: Payment) -> bool:
        return (payment.actor == self.expected_actor
                and payment.booking == self.expected_booking
                and payment.property_id == self.expected_property
                and payment.beneficiary == self.expected_beneficiary
                and payment.route == self.allowed_route
                and payment.amount_minor > 0 and isinstance(payment.amount_minor, int)
                and payment.currency == "EUR" and bool(payment.operation_id))

    def revoke(self) -> None:
        self.revocation_generation += 1

    def change_policy(self) -> None:
        self.policy_generation += 1


class FinalitySink:
    """Atomic local verify+consume+mock-effect under ONE lock (single-process only).

    In a production deployment, this requires a genuine protected transaction and
    effect-capable path closure. This implementation simulates, but does not prove,
    those guarantees. Denial consumes authentic grants to prevent repeated trials.
    """
    def __init__(self, authority: ProtectedAuthority, *, sink_id="payment-sink-A"):
        self.authority = authority
        self.sink_id = sink_id
        self.rail = FakeRail()
        self._consumed: set[str] = set()
        self._decisions: list[str] = []
        self._lock = threading.Lock()
        self.available = True

    @property
    def decision_log(self) -> tuple[str, ...]:
        return tuple(self._decisions)

    def dispatch(self, candidate: Payment, effective: Payment, *, grant: Grant, now: int = 1001, **kwargs) -> Decision:
        # "effective" is the resource-bound command read at this mock sink. It must
        # not be re-read from candidate or from an attacker-supplied approval digest.
        with self._lock:
            return self._dispatch_locked(effective, grant, now)

    def _dispatch_locked(self, effective: Payment, grant: Grant, now: int) -> Decision:
        def deny(reason: str, burn: bool = True) -> Decision:
            if burn:
                self._consumed.add(grant.grant_id)
            self._decisions.append("DENY:" + reason)
            return Decision(False, reason, len(self.rail.events))

        if not self.available:
            return deny("SINK_UNAVAILABLE", burn=False)
        if not self.authority.verify_grant_signature(grant):
            return deny("INVALID_GRANT_SIGNATURE", burn=False)
        if grant.grant_id in self._consumed:
            return deny("REPLAY_OR_PREVIOUS_DENIAL", burn=False)
        # Burn on mismatch for authentic grants; this may produce intentional DoS
        # against a grant if an attacker can submit it. Actual trust placement matters.
        if grant.sink != self.sink_id:
            return deny("WRONG_SINK")
        if now > grant.expires_at:
            return deny("EXPIRED")
        if grant.policy_generation != self.authority.policy_generation:
            return deny("POLICY_CHANGED")
        if grant.revocation_generation != self.authority.revocation_generation:
            return deny("REVOKED")
        if grant.actor != effective.actor or grant.booking != effective.booking or grant.property_id != effective.property_id:
            return deny("CONTEXT_CHANGED")
        actual_digest = hashlib.sha256(canonical(effective.as_descriptor())).hexdigest()
        if not hmac.compare_digest(grant.descriptor_digest, actual_digest):
            return deny("ACTUAL_OPERATION_MISMATCH")
        if not self.authority._allowed_payment(effective):
            return deny("CURRENT_POLICY_DENIED")
        self._consumed.add(grant.grant_id)
        # Local mock of an atomic verify-and-effectuate. NOT atomic with a real PSP.
        self.rail._simulate_effect(effective)
        self._decisions.append("ALLOW")
        return Decision(True, "SINK_COMMITTED_MATCHING_OPERATION", len(self.rail.events))


class IncompleteCandidateCheckingSink(FinalitySink):
    """Intentionally broken: validates candidate, then transformer changes effect.

    The protected signature, revocation and replay checks are real within this
    simulator, but checking the *candidate* at the last purported sink rather
    than the actual final operation leaves a post-check transformation window.
    """
    def dispatch(self, candidate: Payment, effective: Payment, *, grant: Grant, now: int = 1001, **kwargs) -> Decision:
        with self._lock:
            result = self._dispatch_locked(candidate, grant, now)
            if result.allowed:
                # Explicitly simulate an unchecked later connector rewriting the
                # downstream operation after protected candidate validation.
                self.rail.events[-1] = effective
            return result


class NativeTransactionalResourceServer:
    """Strong conventional counterexample: native resource-level exact check.

    Demonstrates that a well-designed resource server + atomic local transaction
    CAN match the guard's modeled deny/allow semantics without a separate
    signed execution artifact. This is illustrative, not an OAuth implementation.
    """
    def __init__(self, authority: ProtectedAuthority):
        self.authority = authority
        self.rail = FakeRail()
        self._approved: dict[str, tuple[Payment, int, int, int]] = {}
        self._used: set[str] = set()
        self._lock = threading.Lock()
        self.available = True

    def approve(self, candidate: Payment, *, now: int = 1000, valid_for: int = 120) -> str:
        if not self.authority._allowed_payment(candidate):
            raise ValueError("resource authorization denied")
        ticket = secrets.token_hex(12)
        self._approved[ticket] = (candidate, self.authority.policy_generation,
                                   self.authority.revocation_generation, now + valid_for)
        return ticket

    def dispatch(self, candidate: Payment, effective: Payment, *, ticket: str, now: int = 1001, **kwargs) -> Decision:
        with self._lock:
            def deny(reason):
                if ticket in self._approved:
                    self._used.add(ticket)
                return Decision(False, reason, len(self.rail.events))
            if not self.available:
                return Decision(False, "RESOURCE_UNAVAILABLE", len(self.rail.events))
            if ticket not in self._approved:
                return deny("UNKNOWN_TICKET")
            if ticket in self._used:
                return deny("RESOURCE_REPLAY")
            approved, policy, revocation, expires = self._approved[ticket]
            if now > expires:
                return deny("RESOURCE_EXPIRED")
            if policy != self.authority.policy_generation or revocation != self.authority.revocation_generation:
                return deny("RESOURCE_STALE_AUTHORITY")
            if effective != approved or not self.authority._allowed_payment(effective):
                return deny("RESOURCE_ACTUAL_OPERATION_MISMATCH")
            self._used.add(ticket)
            self.rail._simulate_effect(effective)
            return Decision(True, "RESOURCE_ATOMIC_NATIVE_ALLOW", len(self.rail.events))


def modified(payment: Payment, **changes) -> Payment:
    return replace(payment, **changes)
