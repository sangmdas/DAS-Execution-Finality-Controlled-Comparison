"""Deterministic attacker-vs-baseline comparison for fictional operations."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import csv
import json
from pathlib import Path
from .model import Payment, CoarseSessionBaseline, UpstreamBoundButUncheckedSink, ProtectedAuthority, FinalitySink, NativeTransactionalResourceServer, IncompleteCandidateCheckingSink, modified


@dataclass
class Outcome:
    scenario: str
    variant: str
    decision: str
    mock_effects: int
    reason: str
    expected: str
    correct: bool


ATTACKS = {
    "valid_transaction": None,
    "beneficiary_substitution": {"beneficiary": "attacker-merchant"},
    "amount_inflation": {"amount_minor": 95500},
    "currency_substitution": {"currency": "USD"},
    "booking_substitution": {"booking": "booking-other"},
    "property_substitution": {"property_id": "other-property"},
    "actor_substitution": {"actor": "unknown-operator"},
    "operation_id_substitution": {"operation_id": "op-injected"},
    "alternate_route": {"route": "connector-direct-route"},
}


def evaluate_one(scenario: str, variant: str) -> Outcome:
    base = Payment()
    expected_allow = scenario == "valid_transaction"
    effective = modified(base, **(ATTACKS[scenario] or {}))
    if variant == "session_only":
        engine = CoarseSessionBaseline()
        decision = engine.dispatch(base, effective)
    elif variant == "upstream_only":
        engine = UpstreamBoundButUncheckedSink()
        ticket = engine.approve(base)
        decision = engine.dispatch(base, effective, ticket=ticket)
    elif variant == "candidate_checked_then_mutated":
        authority = ProtectedAuthority()
        grant = authority.approve(base)
        engine = IncompleteCandidateCheckingSink(authority)
        decision = engine.dispatch(base, effective, grant=grant)
    elif variant == "native_atomic_resource":
        authority = ProtectedAuthority()
        engine = NativeTransactionalResourceServer(authority)
        ticket = engine.approve(base)
        decision = engine.dispatch(base, effective, ticket=ticket)
    elif variant == "sink_guard":
        authority = ProtectedAuthority()
        grant = authority.approve(base)
        engine = FinalitySink(authority)
        decision = engine.dispatch(base, effective, grant=grant)
    else:
        raise ValueError(variant)
    return Outcome(scenario=scenario, variant=variant,
                   decision="ALLOW" if decision.allowed else "DENY",
                   mock_effects=decision.event_count, reason=decision.reason,
                   expected="ALLOW" if expected_allow else "DENY",
                   correct=decision.allowed == expected_allow)


def evaluate_stateful(scenario: str, variant: str) -> Outcome:
    base = Payment()
    auth = ProtectedAuthority()
    sink = FinalitySink(auth)
    grant = auth.approve(base, now=1000)
    session = CoarseSessionBaseline()
    upstream = UpstreamBoundButUncheckedSink()
    ticket = upstream.approve(base)
    native = NativeTransactionalResourceServer(auth)
    ticket_native = native.approve(base, now=1000)
    if scenario == "revoked_after_approval":
        auth.revoke()
    elif scenario == "policy_changed_after_approval":
        auth.change_policy()
    elif scenario == "expired_approval":
        pass
    else:
        raise ValueError(scenario)
    now = 1400 if scenario == "expired_approval" else 1001
    if variant == "session_only":
        result = session.dispatch(base, base)
    elif variant == "upstream_only":
        result = upstream.dispatch(base, base, ticket=ticket)
    elif variant == "candidate_checked_then_mutated":
        incomplete = IncompleteCandidateCheckingSink(auth)
        result = incomplete.dispatch(base, base, grant=grant, now=now)
    elif variant == "native_atomic_resource":
        result = native.dispatch(base, base, ticket=ticket_native, now=now)
    else:
        result = sink.dispatch(base, base, grant=grant, now=now)
    return Outcome(scenario, variant, "ALLOW" if result.allowed else "DENY",
                   result.event_count, result.reason, "DENY", not result.allowed)


def evaluate_replay(variant: str) -> Outcome:
    base = Payment()
    if variant == "session_only":
        engine = CoarseSessionBaseline()
        first = engine.dispatch(base, base)
        second = engine.dispatch(base, base)
    elif variant == "upstream_only":
        engine = UpstreamBoundButUncheckedSink()
        ticket = engine.approve(base)
        first = engine.dispatch(base, base, ticket=ticket)
        second = engine.dispatch(base, base, ticket=ticket)
    elif variant == "candidate_checked_then_mutated":
        auth = ProtectedAuthority()
        engine = IncompleteCandidateCheckingSink(auth)
        grant = auth.approve(base)
        first = engine.dispatch(base, base, grant=grant)
        second = engine.dispatch(base, base, grant=grant)
    elif variant == "native_atomic_resource":
        auth = ProtectedAuthority()
        engine = NativeTransactionalResourceServer(auth)
        ticket = engine.approve(base)
        first = engine.dispatch(base, base, ticket=ticket)
        second = engine.dispatch(base, base, ticket=ticket)
    else:
        auth = ProtectedAuthority()
        engine = FinalitySink(auth)
        grant = auth.approve(base)
        first = engine.dispatch(base, base, grant=grant)
        second = engine.dispatch(base, base, grant=grant)
    assert first.allowed  # affirmative control
    return Outcome("replay_same_authorization", variant,
                   "ALLOW" if second.allowed else "DENY", second.event_count,
                   second.reason, "DENY", not second.allowed)


def outcomes() -> list[Outcome]:
    rows = []
    for attack in ATTACKS:
        for variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
            rows.append(evaluate_one(attack, variant))
    for attack in ("revoked_after_approval", "policy_changed_after_approval", "expired_approval"):
        for variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
            rows.append(evaluate_stateful(attack, variant))
    for variant in ("session_only", "upstream_only", "candidate_checked_then_mutated", "native_atomic_resource", "sink_guard"):
        rows.append(evaluate_replay(variant))
    return rows


def write_reports(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    rows = outcomes()
    with (destination / "attack_matrix.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0])))
        writer.writeheader()
        writer.writerows(asdict(r) for r in rows)
    with (destination / "attack_matrix.json").open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2)
    by_scenario: dict[str, dict[str, Outcome]] = {}
    for r in rows:
        by_scenario.setdefault(r.scenario, {})[r.variant] = r
    lines = ["# Measured outcomes from synthetic local execution", "",
             "These are deliberately incomplete comparator designs, **not** representative measurements of OAuth, Envoy, RATS or production platforms.", "",
             "- `ALLOW` means an event was appended to a fake in-memory payment rail, never a real transfer.",
             "- `DENY` means this one controlled code path refused the mock operation.",
             "- `!` marks a purposely vulnerable variant failing the specified expectation.", "",
             "| Synthetic attack | Expected | Session-only | Upstream-only | Candidate checked then mutated | Native transactional resource | Sink guard |", "|---|---|---|---|---|---|---|"]
    for scenario, entries in by_scenario.items():
        label = lambda kind: (entries[kind].decision + (" !" if not entries[kind].correct else ""))
        lines.append(f"| {scenario.replace('_',' ')} | {entries['sink_guard'].expected} | {label('session_only')} | {label('upstream_only')} | {label('candidate_checked_then_mutated')} | {label('native_atomic_resource')} | {label('sink_guard')} |")
    lines.extend(["", "## Interpretation", "", "This supports a claim about **the five implementations in this repository only**. The failing comparators are intentionally missing enforcement checks; showing their failure does not establish novelty over existing standards or real deployments. The guard depends on a trusted ingress, non-bypassable sink and atomic state; these are assumptions in the mock, not infrastructure evidence.", "", "To rerun: `python -m finality_lab.experiments`. Report generator overwrites the matrix with fresh local outcomes."])
    (destination / "ATTACK_MATRIX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(rows)} scenario×variant observations to {destination}")
    flaws = sum(not r.correct for r in rows if r.variant in ("session_only", "upstream_only", "candidate_checked_then_mutated"))
    secure = sum(r.correct for r in rows if r.variant == "sink_guard")
    print(f"Deliberately weak comparator failures: {flaws}; sink-guard correct: {secure}/{sum(r.variant == 'sink_guard' for r in rows)}; native-resource correct: {sum(r.correct for r in rows if r.variant == 'native_atomic_resource')}")


if __name__ == "__main__":
    write_reports(Path("reports"))
