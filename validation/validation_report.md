# Aegis-Broker — Validation & Verification Report

Date: 2026-10-30

## 1. Validation Summary

| Validation | Result |
|---|---|
| Python syntax checks | PASS |
| Shell syntax checks | PASS |
| TOML configuration | PASS |
| Docker environment build | PASS |
| Harbor CLI 0.24.0 | Available |
| RustLabs static checker | PASS |
| Harbor Oracle | PASS — Mean: 1.000 |
| Harbor NOP | PASS — Mean: 0.000 |

## 2. Latest Harbor Evaluations

### Oracle reference solution

Command: `harbor run -p . -a oracle`

- Trials: 1
- Exceptions: 0
- Mean: 1.000
- Reward: 1.0
- Runtime: 57 seconds
- Job: `jobs/2026-10-30__12-31-57`

### NOP baseline

Command: `harbor run -p . -a nop`

- Trials: 1
- Exceptions: 0
- Mean: 0.000
- Reward: 0.0
- Runtime: 40 seconds
- Job: `jobs/2026-10-30__12-33-01`

Both evaluations were run after the agent timeout was set to 72,000 seconds.

## 3. RustLabs Static Checker

Command: `python3 ~/Downloads/frontierswe-check.py .`

Result:


The checker reported no FAIL or WARN findings at the time of this run.


## 4. Oracle Domain Scores

| Domain | Weight | Positive tests | Attack tests | Score |
|---|---:|---:|---:|---:|
| D1: Capability tokens and delegation | 0.25 | 2/2 | 4/4 | 0.250 |
| D2: Path canonicalization and symlinks | 0.20 | 2/2 | 4/4 | 0.200 |
| D3: SQLite authorization and isolation | 0.15 | 2/2 | 4/4 | 0.150 |
| D4: Session taint and HITL receipts | 0.20 | 2/2 | 4/4 | 0.200 |
| D5: Audit ratcheting and recovery | 0.20 | 2/2 | 4/4 | 0.200 |
| **Total** | **1.00** | **10/10** | **20/20** | **1.000** |

The recorded Oracle evaluation passed all 30 tests.

## 5. Task Architecture

Aegis-Broker evaluates five security domains:

1. Chained HMAC-SHA256 capability tokens, caveat narrowing, quotas, and revocation.
2. Filesystem path canonicalization, containment, Unicode normalization, and symlink protections.
3. SQLite authorization, read-only enforcement, and connection isolation.
4. Session taint tracking and single-use human approval receipts.
5. Tamper-evident audit chaining, crash recovery, and fail-closed corruption handling.

The task uses a containerized environment and a verifier that calculates a weighted score from automated tests.

## 6. Reproduction Commands

Run from the task root:

- `python3 -m compileall -q environment/workspace/app environment/workspace/scripts tests solution`
- `bash -n solution/solve.sh`
- `bash -n tests/test.sh`
- `python3 ~/Downloads/frontierswe-check.py .`
- `harbor run -p . -a oracle`
- `harbor run -p . -a nop`

Expected Harbor results:

- Oracle: Mean 1.000
- NOP: Mean 0.000

## 7. Validation Limitations

Passing automated tests and static checks does not prove the absence of all security vulnerabilities. These results demonstrate that the reference solution passed the implemented test suite and that the task package passed the checks performed by the RustLabs static checker. Independent security review may identify edge cases not covered by the current tests.
