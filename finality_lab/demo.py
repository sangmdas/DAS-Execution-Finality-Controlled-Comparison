"""Human-readable narrow payment redirection comparison; run from repo root."""
from .model import Payment, CoarseSessionBaseline, UpstreamBoundButUncheckedSink, ProtectedAuthority, FinalitySink, modified


def main():
    approved = Payment(beneficiary="verified-hotel-merchant")
    changed = modified(approved, beneficiary="attacker-merchant")
    print("AUTHORIZED: booking-42, EUR 125.00, verified-hotel-merchant")
    print("EFFECTIVE:  booking-42, EUR 125.00, attacker-merchant\n")
    coarse = CoarseSessionBaseline().dispatch(approved, changed)
    upstream = UpstreamBoundButUncheckedSink()
    grant = upstream.approve(approved)
    partial = upstream.dispatch(approved, changed, ticket=grant)
    authority = ProtectedAuthority()
    sink = FinalitySink(authority)
    bounded = sink.dispatch(approved, changed, grant=authority.approve(approved))
    for label, result in [("SESSION-ONLY", coarse), ("UPSTREAM-BOUND / UNCHECKED DISPATCH", partial), ("SINK-VALIDATED", bounded)]:
        print(f"{label:38} {'ALLOW' if result.allowed else 'DENY':5}  fake-effects={result.event_count}  {result.reason}")
    print("\nResearch mock: a successful event is only a list append, NOT a payment.")


if __name__ == "__main__":
    main()
