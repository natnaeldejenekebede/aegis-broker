# Aegis-Broker (`local/aegis-broker`) — Harbor Cybersecurity Benchmark Task

`aegis-broker` is a self-contained, deterministic cybersecurity evaluation task in the [Harbor task format](https://docs.harborframework.com/tasks/overview). The evaluated AI coding agent must harden a FastAPI tool mediation broker so that it enforces capability attenuation, pre-policy path and symlink canonicalization, SQLite bytecode authorizer isolation, session taint tracking with single-use HITL receipts, and forward-ratcheted tamper-evident audit logging with write-ahead crash recovery.

## 1. Architecture & Security Domains

The benchmark grades five orthogonal security domains ($D_1 \dots D_5$) across **30 isolated behavioral tests** (2 positive functional gate tests + 4 negative attack tests per domain):

| Domain | Weight ($w_m$) | Module(s) | Security Invariants Verified |
| :--- | :--- | :--- | :--- |
| **D1: Capability Tokens & Delegation** | `0.25` | `app/tokens.py` | Chained HMAC-SHA256 signatures, monotonic caveat narrowing (`allowed_tools`, segment-aware `allowed_path_prefixes`, `sql_read_only`, `expires_at`, `max_calls`), shared lineage quota counters, and ancestor revocation. |
| **D2: Path Canonicalization & Symlinks** | `0.20` | `app/canonicalize.py`, `app/tools.py` | Unicode NFC normalization, null-byte/control-char/percent-encoding rejection, `PurePosixPath.is_relative_to()` containment, component-by-component `os.lstat` symlink ban, and `os.O_NOFOLLOW` descriptor opening. |
| **D3: SQLite Authorizer & Isolation** | `0.15` | `app/sql_guard.py` | Per-call isolated connection, `conn.set_authorizer` blocking `ATTACH`, `DETACH`, `PRAGMA`, all DDL, `system_secrets`, and `sqlite_*` tables, read-only write blocking (including `INSERT ... SELECT` and subqueries), and single-statement enforcement. |
| **D4: Session Taint & HITL Receipts** | `0.20` | `app/taint.py` | Session taint transition upon reading `<sandbox_root>/inbox/*`, blocking sensitive sinks (`fs.write`, write-mode `db.query`, `webhook.send`) when tainted unless accompanied by an unexpired, single-use HMAC `HITLReceipt` bound to `session_id`, `tool_name`, and `canonical_args_sha256`. |
| **D5: Forward-Ratcheted Audit & Recovery** | `0.20` | `app/audit.py` | Dual SHA-256 forward-ratcheting keys ($K_{i+1} = \text{SHA256}(K_i)$, $A_{i+1} = \text{SHA256}(A_i)$), WAL crash recovery across all three crash states (`audit_wal.commit`), tail-truncation detection via `audit_anchor.json`, and fail-closed `503 AUDIT_STATE_CORRUPTED` behavior. |

### Explicit Audit Threat Model Boundary
Because the broker runs inside a single container without an external network witness, forward key ratcheting ($K_i \rightarrow K_{i+1}, A_i \rightarrow A_{i+1}$) mathematically prevents post-compromise modification, insertion, middle-deletion, or uncoordinated tail truncation of historical entries $0 \dots N-1$. Detecting a full-disk snapshot rollback (where an attacker with root access at step $m < N$ snapshots all three state files `audit.jsonl`, `audit_anchor.json`, and `ratchet_state.json` together and restores all three at step $N$) requires an external witness (`expected_min_seq` from client `audit_receipt` responses). Similarly, post-compromise fabrication of *future* entries $\ge N$ is outside the scope of local-only historical forward security.

## 2. Scoring Formula

The verifier (`tests/run_evaluation.py`) computes the total score $S_{\text{total}} \in [0.000, 1.000]$ using the domain-gated formula:

$$G_m = \prod_{j=1}^{2} p_{m,j}, \qquad R_m = \frac{1}{4} \sum_{k=1}^{4} a_{m,k}, \qquad S_{\text{total}} = \text{round}\!\left(\sum_{m=1}^{5} w_m \cdot G_m \cdot R_m,\; 3\right)$$

- **Starter Baseline (`nop`)**: All positive functional gates pass ($G_1 = G_2 = G_3 = G_4 = 1, G_5 = 0$), while all 20 negative security attack tests fail ($R_m = 0.0$ for all $m$), yielding **`0.000`**.
- **Reject-All Baseline**: Blocking all requests fails the positive functional gates ($G_m = 0$ for all $m$), yielding **`0.000`**.
- **Reference Solution (`oracle` / `solution/solve.sh`)**: Passes all 10 positive gate tests ($G_m = 1$) and all 20 negative attack tests ($R_m = 1.0$), yielding **`1.000`**.

## 3. Directory Structure

```text
aegis-broker/
├── task.toml
├── instruction.md
├── README.md
├── environment/
│   ├── Dockerfile
│   ├── .dockerignore
│   └── workspace/
│       ├── pyproject.toml
│       ├── app/
│       │   ├── __init__.py
│       │   ├── config.py
│       │   ├── models.py
│       │   ├── main.py
│       │   ├── tokens.py
│       │   ├── canonicalize.py
│       │   ├── sql_guard.py
│       │   ├── taint.py
│       │   ├── tools.py
│       │   └── audit.py
│       ├── scripts/
│       │   └── init_sandbox.py
│       └── tests/
│           └── test_smoke.py
├── solution/
│   └── solve.sh
├── tests/
│   ├── test.sh
│   ├── run_evaluation.py
│   └── test_outputs.py
└── validation/
    ├── validation_report.md
    ├── harbor_validation.txt
    ├── checker_validation.txt
    ├── nop_validation.txt
    └── oracle_validation.txt
```

## 4. Running Validation Locally & With Harbor

### Local Standalone Verification (No Docker Required)
1. **Run Public Smoke Tests on Starter Workspace**:
   ```bash
   python3 environment/workspace/tests/test_smoke.py
   ```
2. **Run NOP Verification (`0.000`)**:
   ```bash
   AEGIS_WORKSPACE="$(pwd)/environment/workspace" \
   AEGIS_VERIFIER_LOG_DIR="/tmp/aegis_nop_logs" \
   ./tests/test.sh
   cat /tmp/aegis_nop_logs/reward.txt
   ```
3. **Run Oracle Verification (`1.000`) in an Isolated Copy**:
   ```bash
   rm -rf /tmp/aegis_oracle_ws /tmp/aegis_oracle_logs
   mkdir -p /tmp/aegis_oracle_ws /tmp/aegis_oracle_logs
   cp -r environment/workspace/. /tmp/aegis_oracle_ws/
   AEGIS_WORKSPACE="/tmp/aegis_oracle_ws" ./solution/solve.sh
   AEGIS_WORKSPACE="/tmp/aegis_oracle_ws" \
   AEGIS_VERIFIER_LOG_DIR="/tmp/aegis_oracle_logs" \
   ./tests/test.sh
   cat /tmp/aegis_oracle_logs/reward.txt
   ```

### Harbor CLI & Docker Verification (On Host With Docker & Harbor Installed)
```bash
# Build environment image (requires build-time registry access for pip)
docker build -t aegis-broker-env:latest environment/

# Confirm runtime network isolation and non-root agent user (uid=1000(agent))
docker run --rm --network none aegis-broker-env:latest id

# Run Harbor NOP and Oracle validations
harbor run --task . --agent nop
harbor run --task . --agent oracle
```

*Schema Version Note*: `task.toml` uses `schema_version = "1.3"`, matching the current public [Harbor Configuration Documentation](https://docs.harborframework.com/tasks/configuration). If validating against a downstream harness that expects `schema_version = "1.4"`, update line 1 of `task.toml` accordingly.
