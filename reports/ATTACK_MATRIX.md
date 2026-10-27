# Measured outcomes from synthetic local execution

These are deliberately incomplete comparator designs, **not** representative measurements of OAuth, Envoy, RATS or production platforms.

- `ALLOW` means an event was appended to a fake in-memory payment rail, never a real transfer.
- `DENY` means this one controlled code path refused the mock operation.
- `!` marks a purposely vulnerable variant failing the specified expectation.

| Synthetic attack | Expected | Session-only | Upstream-only | Candidate checked then mutated | Native transactional resource | Sink guard |
|---|---|---|---|---|---|---|
| valid transaction | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| beneficiary substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| amount inflation | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| currency substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| booking substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| property substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| actor substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| operation id substitution | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| alternate route | DENY | ALLOW ! | ALLOW ! | ALLOW ! | DENY | DENY |
| revoked after approval | DENY | ALLOW ! | ALLOW ! | DENY | DENY | DENY |
| policy changed after approval | DENY | ALLOW ! | ALLOW ! | DENY | DENY | DENY |
| expired approval | DENY | ALLOW ! | ALLOW ! | DENY | DENY | DENY |
| replay same authorization | DENY | ALLOW ! | ALLOW ! | DENY | DENY | DENY |

## Interpretation

This supports a claim about **the five implementations in this repository only**. The failing comparators are intentionally missing enforcement checks; showing their failure does not establish novelty over existing standards or real deployments. The guard depends on a trusted ingress, non-bypassable sink and atomic state; these are assumptions in the mock, not infrastructure evidence.

To rerun: `python -m finality_lab.experiments`. Report generator overwrites the matrix with fresh local outcomes.
