# Local execution environment and evidence

**Test suite:** 96 executed unittest cases; 0 failures.

**Attack matrix:** 13 scenarios x 5 designs = 65 outcomes.

**Expected security failures in intentionally incomplete implementations:** 32 observations (12 session-only, 12 upstream-only, 8 candidate-check-then-mutate). **All 13** sink-guard and **all 13** native-resource decisions matched expected outcomes.

**Important:** No external payment or network operation occurred. No third-party review or production-scale latency test was performed.

## Local runtime

```text
Python 3.13.5
Linux 6.18.55 x86_64
```

## Reproduction

```sh
python3 -m finality_lab.demo
python3 -m unittest discover -s tests -v
python3 -m finality_lab.experiments
```

Reports generated locally from executable source. Results on other machines should be independently reproduced and recorded, not assumed.
