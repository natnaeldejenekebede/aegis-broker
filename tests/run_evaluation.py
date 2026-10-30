from __future__ import annotations

import argparse
import json
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Callable


DOMAIN_CONFIG = [
    {
        "id": "D1",
        "name": "Capability Tokens & Delegation",
        "weight": 0.25,
        "positive": [
            "test_pos_d1_root_mint_and_invoke",
            "test_pos_d1_multi_hop_valid_attenuation",
        ],
        "negative": [
            "test_neg_d1_forged_or_stripped_hmac_chain",
            "test_neg_d1_child_widens_tools_prefixes_or_ttl",
            "test_neg_d1_lineage_quota_exhaustion_across_children",
            "test_neg_d1_ancestor_hop_revocation",
        ],
    },
    {
        "id": "D2",
        "name": "Filesystem Path Canonicalization & Symlinks",
        "weight": 0.20,
        "positive": [
            "test_pos_d2_nested_sandbox_read_write",
            "test_pos_d2_normalized_dot_segments_in_prefix",
        ],
        "negative": [
            "test_neg_d2_percent_encoding_and_null_byte",
            "test_neg_d2_dotdot_escape_outside_prefix",
            "test_neg_d2_sibling_directory_prefix_collision",
            "test_neg_d2_leaf_and_intermediate_symlink_rejected",
        ],
    },
    {
        "id": "D3",
        "name": "SQLite Authorizer & Transaction Safety",
        "weight": 0.15,
        "positive": [
            "test_pos_d3_readonly_select_queries",
            "test_pos_d3_readwrite_insert_and_update",
        ],
        "negative": [
            "test_neg_d3_readonly_blocks_insert_and_cte_delete",
            "test_neg_d3_blocks_attach_pragma_and_ddl",
            "test_neg_d3_blocks_system_secrets_and_sqlite_master",
            "test_neg_d3_blocks_stacked_multi_statements",
        ],
    },
    {
        "id": "D4",
        "name": "Session Taint Tracking & HITL Receipts",
        "weight": 0.20,
        "positive": [
            "test_pos_d4_clean_sinks_and_tainted_reads_succeed",
            "test_pos_d4_tainted_sink_with_valid_hitl_receipt",
        ],
        "negative": [
            "test_neg_d4_tainted_blocks_fs_sql_webhook_sinks",
            "test_neg_d4_hitl_nonce_replay_blocked",
            "test_neg_d4_hitl_modified_args_or_expired_blocked",
            "test_neg_d4_second_sink_after_single_receipt_blocked",
        ],
    },
    {
        "id": "D5",
        "name": "Forward-Ratcheted Audit & Crash Recovery",
        "weight": 0.20,
        "positive": [
            "test_pos_d5_mixed_ledger_and_anchor_verify",
            "test_pos_d5_wal_crash_recovery_all_three_cases",
        ],
        "negative": [
            "test_neg_d5_detects_mutated_historical_entry",
            "test_neg_d5_detects_resign_with_dumped_ratchet_key",
            "test_neg_d5_detects_tail_truncation_and_rollback",
            "test_neg_d5_unrecoverable_tamper_fails_closed_503",
        ],
    },
]


def _run_single_test(fn: Callable[[Path], None]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="aegis_eval_") as td:
        try:
            fn(Path(td))
            return 1, "PASS"
        except Exception as exc:
            tb = traceback.format_exc(limit=4)
            return 0, f"FAIL: {exc.__class__.__name__}: {exc}\n{tb}"


def evaluate_suite(workspace_dir: Path, reward_dir: Path) -> float:
    tests_dir = Path(__file__).resolve().parent
    if str(workspace_dir) not in sys.path:
        sys.path.insert(0, str(workspace_dir))
    if str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))

    import test_outputs  # type: ignore[import-not-found]

    domain_summaries: dict[str, dict[str, object]] = {}
    total_score_raw = 0.0
    total_passed = 0
    total_tests = 0

    print("=" * 72)
    print("AEGIS-BROKER HARBOR VERIFIER EVALUATION")
    print("=" * 72)

    for dom in DOMAIN_CONFIG:
        dom_id = str(dom["id"])
        dom_name = str(dom["name"])
        weight = float(dom["weight"])  # type: ignore[arg-type]
        pos_names: list[str] = list(dom["positive"])  # type: ignore[arg-type]
        neg_names: list[str] = list(dom["negative"])  # type: ignore[arg-type]

        print(f"\n[{dom_id}] {dom_name} (weight={weight:.2f})")
        pos_results: list[int] = []
        for tname in pos_names:
            total_tests += 1
            fn = getattr(test_outputs, tname)
            res, msg = _run_single_test(fn)
            pos_results.append(res)
            total_passed += res
            status_str = "PASS" if res == 1 else "FAIL"
            print(f"  [POS] {tname}: {status_str}")
            if res == 0:
                for line in msg.splitlines()[:3]:
                    print(f"        {line}")

        neg_results: list[int] = []
        for tname in neg_names:
            total_tests += 1
            fn = getattr(test_outputs, tname)
            res, msg = _run_single_test(fn)
            neg_results.append(res)
            total_passed += res
            status_str = "PASS" if res == 1 else "FAIL"
            print(f"  [NEG] {tname}: {status_str}")
            if res == 0:
                for line in msg.splitlines()[:3]:
                    print(f"        {line}")

        # G_m = product of the two positive test results in domain m
        gate_m = 1
        for p in pos_results:
            gate_m *= p

        # R_m = sum of the four negative attack test results divided by 4
        attack_rate_m = sum(neg_results) / 4.0

        # S_m = w_m * G_m * R_m
        score_m = weight * gate_m * attack_rate_m
        total_score_raw += score_m

        print(
            f"  -> Gate G_{dom_id}={gate_m} | Attack Rate R_{dom_id}={attack_rate_m:.2f} "
            f"({sum(neg_results)}/4) | Domain Score S_{dom_id}={score_m:.4f}"
        )

        domain_summaries[dom_id] = {
            "weight": weight,
            "positive_passed": sum(pos_results),
            "positive_total": len(pos_results),
            "gate": gate_m,
            "negative_passed": sum(neg_results),
            "negative_total": len(neg_results),
            "attack_rate": attack_rate_m,
            "domain_score": round(score_m, 6),
        }

    final_score = round(total_score_raw, 3)
    print("\n" + "=" * 72)
    print(f"TOTAL TESTS PASSED: {total_passed} / {total_tests}")
    print(f"FINAL REWARD SCORE: {final_score:.3f}")
    print(f"Mean: {final_score:.3f}")
    print("=" * 72)

    reward_dir.mkdir(parents=True, exist_ok=True)
    (reward_dir / "reward.txt").write_text(f"{final_score:.3f}\n", encoding="utf-8")
    report = {
        "reward": final_score,
        "tests_passed": total_passed,
        "tests_total": total_tests,
        "domains": domain_summaries,
    }

    # Harbor requires numeric values at the top level of reward.json.
    (reward_dir / "reward.json").write_text(
        json.dumps({"reward": final_score}, indent=2) + "\n",
        encoding="utf-8",
    )

    # Keep detailed domain metrics in a separate report.
    (reward_dir / "evaluation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return final_score


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Aegis-Broker Harbor evaluation")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/workspace"),
        help="Path to agent workspace containing app/",
    )
    parser.add_argument(
        "--reward-dir",
        type=Path,
        default=Path("/logs/verifier"),
        help="Directory to write reward.txt and reward.json",
    )
    args = parser.parse_args()
    evaluate_suite(args.workspace.resolve(), args.reward_dir.resolve())


if __name__ == "__main__":
    main()
