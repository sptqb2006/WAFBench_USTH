#!/usr/bin/env python3
"""
Metrics Calculation, PostgreSQL Event-DB Sync & Comparable Benchmark Report
(Table 5.2 & 5.3 + Comparable Benchmark: 3-Tier WAFBench vs HTTP-Status-Only)
"""

import argparse
import os
import pandas as pd

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    psycopg2 = None
    RealDictCursor = None
    PSYCOPG2_AVAILABLE = False

BENIGN_LABELS = ("benign", "edge")
VALID_CELLS = ("TP_D", "FN_D", "FP_D", "TN_D", "TP_B", "FN_B", "FP_B", "TN_B")


def get_event_db_config() -> dict:
    return {
        "host": os.getenv("EVENT_DB_HOST", "localhost"),
        "port": int(os.getenv("EVENT_DB_PORT", "5432")),
        "dbname": os.getenv("EVENT_DB_NAME", "wafbench_events"),
        "user": os.getenv("EVENT_DB_USER", "telemetry_user"),
        "password": os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
    }


def _get_db_connection():
    if not PSYCOPG2_AVAILABLE:
        raise RuntimeError("psycopg2-binary is required for PostgreSQL event-db access.")
    cfg = get_event_db_config()
    return psycopg2.connect(
        host=cfg["host"],
        port=cfg["port"],
        dbname=cfg["dbname"],
        user=cfg["user"],
        password=cfg["password"],
        cursor_factory=RealDictCursor,
    )


def load_events_from_db(batch_id: str = None, run_id: str = None) -> list:
    """
    Loads correlated events from PostgreSQL normalized_events table.
    Excludes rows still in PENDING_TELEMETRY from metric evaluation while
    preserving full row metadata for audit and validity accounting.
    """
    clauses = ["(metric_cell IS NULL OR metric_cell <> 'PENDING_TELEMETRY')"]
    params = []
    if batch_id:
        clauses.append("batch_id = %s")
        params.append(batch_id)
    if run_id:
        clauses.append("run_id = %s")
        params.append(run_id)

    where_sql = " AND ".join(clauses)
    query = f"""
        SELECT
            run_id,
            batch_id,
            case_id,
            family_id AS family,
            label,
            state,
            repetition,
            correlation_id,
            client_status,
            detected,
            backend_effect,
            validity,
            invalid_reason,
            verdict,
            metric_cell,
            inbound_score,
            disruptive_action
        FROM normalized_events
        WHERE {where_sql}
        ORDER BY id ASC
    """
    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return rows


def save_metrics_to_db(metrics: dict, batch_id: str, config_revision: str = "C0", regression_pass_rate=None) -> int:
    """Persists computed batch metrics into PostgreSQL evaluation_metrics table."""
    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO evaluation_metrics (
                    batch_id,
                    config_revision,
                    total_attempted,
                    total_evaluable,
                    total_invalid,
                    total_inconclusive,
                    detection_rate,
                    blocking_rate,
                    detection_fpr,
                    blocking_fpr,
                    regression_pass_rate
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    batch_id,
                    config_revision,
                    int(metrics.get("attempted", 0)),
                    int(metrics.get("valid", 0)),
                    int(metrics.get("invalid", 0)),
                    int(metrics.get("inconclusive", 0)),
                    metrics.get("detection_rate"),
                    metrics.get("blocking_rate"),
                    metrics.get("detection_fpr"),
                    metrics.get("blocking_fpr"),
                    regression_pass_rate,
                ),
            )
            inserted_id = cur.fetchone()["id"]
        conn.commit()
    finally:
        conn.close()
    print(f"[+] Saved evaluation_metrics row id={inserted_id} (batch_id={batch_id}, rev={config_revision})")
    return inserted_id


def baseline_ok(case_runs: pd.DataFrame, case: dict) -> tuple:
    """
    Direct-to-App runs of one case must behave as the label says:
    malicious -> effect on every rep; benign/edge -> no effect and an expected status.
    """
    if case_runs.empty:
        return False, "No Direct-to-App run"
    if (case_runs["validity"] != "VALID").any():
        return False, "Direct-to-App run invalid"

    expected = case.get("expected_status")
    if case["label"] == "malicious":
        if not case_runs["backend_effect"].all():
            return False, "Attack had no backend effect without WAF"
        return True, ""
    if case_runs["backend_effect"].any():
        return False, "Benign request produced a backend effect"
    statuses = case_runs["client_status"].astype(int)
    seen = sorted(int(s) for s in statuses.unique())
    if expected:
        allowed = expected if isinstance(expected, list) else [expected]
        if not statuses.isin(allowed).all():
            return False, f"Direct status {seen} not in expected {allowed}"
    elif not statuses.between(200, 399).all():
        return False, f"Direct status {seen} is not 2xx/3xx"
    return True, ""


def apply_baseline_gate(results: list, cases: list) -> list:
    """Marks WAF-state runs of a case that failed its baseline as I_BASELINE_CONFLICT."""
    df = pd.DataFrame(results)
    failed = {}
    for case in cases:
        runs = df[(df["case_id"] == case["case_id"]) & (df["state"] == "Direct-to-App")]
        ok, reason = baseline_ok(runs, case)
        if not ok:
            failed[case["case_id"]] = reason

    for r in results:
        r["baseline_ok"] = r["case_id"] not in failed
        if r["case_id"] in failed and r["state"] != "Direct-to-App" and r["validity"] == "VALID":
            r["validity"] = "I_BASELINE_CONFLICT"
            r["invalid_reason"] = failed[r["case_id"]]
    return results


def mark_flaky(results: list) -> list:
    """A (case, state) is flaky when its valid repetitions land in different metric cells."""
    cells = {}
    for r in results:
        if r["validity"] == "VALID":
            cells.setdefault((r["case_id"], r["state"]), set()).add(r["metric_cell"])
    for r in results:
        r["flaky"] = len(cells.get((r["case_id"], r["state"]), set())) > 1
    return results


def _rate(num: int, den: int):
    return round(num / den * 100, 2) if den else None


def calculate_metrics(results: list) -> dict:
    df = pd.DataFrame(results)
    if df.empty:
        return {}

    waf = df[df["state"] != "Direct-to-App"]
    if "metric_cell" in waf.columns:
        waf = waf[waf["metric_cell"] != "PENDING_TELEMETRY"]
    valid = waf[waf["validity"] == "VALID"]
    count = valid["metric_cell"].value_counts().to_dict()
    c = {k: int(count.get(k, 0)) for k in VALID_CELLS}

    return {
        "attempted": len(waf),
        "valid": len(valid),
        "invalid": int(waf["validity"].astype(str).str.startswith("E_").sum()),
        "inconclusive": int(waf["validity"].astype(str).str.startswith("I_").sum()),
        **{k.lower(): v for k, v in c.items()},
        "detection_rate": _rate(c["TP_D"], c["TP_D"] + c["FN_D"]),
        "blocking_rate": _rate(c["TP_B"], c["TP_B"] + c["FN_B"]),
        "detection_fpr": _rate(c["FP_D"], c["FP_D"] + c["TN_D"]),
        "blocking_fpr": _rate(c["FP_B"], c["FP_B"] + c["TN_B"]),
        "flaky_pairs": int(df[df["flaky"]][["case_id", "state"]].drop_duplicates().shape[0]) if "flaky" in df else 0,
    }


def calculate_http_status_only_metrics(results: list) -> dict:
    """
    Comparable Baseline (HTTP-Status-Only, e.g., GoTestWAF / stateless scanner model):
    Evaluates Blocking mode purely by client_status == 403 (blocked) vs != 403 (allowed),
    ignoring ModSecurity audit attribution and independent Backend Oracle verification.
    """
    df = pd.DataFrame(results)
    if df.empty:
        return {}

    block = df[df["state"] == "Blocking"].copy()
    if block.empty:
        return {}

    statuses = pd.to_numeric(block["client_status"], errors="coerce")
    mal = block[block["label"] == "malicious"]
    ben = block[block["label"].isin(BENIGN_LABELS)]

    mal_status = pd.to_numeric(mal["client_status"], errors="coerce")
    ben_status = pd.to_numeric(ben["client_status"], errors="coerce")

    tp_b = int((mal_status == 403).sum())
    fn_b = int((mal_status != 403).sum())
    fp_b = int((ben_status == 403).sum())
    tn_b = int((ben_status != 403).sum())

    validity_series = block["validity"].astype(str) if "validity" in block.columns else pd.Series([], dtype=str)
    unattributed = int((validity_series == "I_UNATTRIBUTED").sum())
    baseline_conflict = int((validity_series == "I_BASELINE_CONFLICT").sum())
    corr_err = int((validity_series == "E_CORRELATION").sum())

    return {
        "attempted_blocking": int(len(block)),
        "http_only_tp_b": tp_b,
        "http_only_fn_b": fn_b,
        "http_only_fp_b": fp_b,
        "http_only_tn_b": tn_b,
        "http_only_blocking_rate": _rate(tp_b, tp_b + fn_b),
        "http_only_blocking_fpr": _rate(fp_b, fp_b + tn_b),
        "unattributed_noise": unattributed,
        "baseline_conflict_noise": baseline_conflict,
        "correlation_error_noise": corr_err,
        "total_misclassified_risk": unattributed + baseline_conflict + corr_err,
        "non_2xx_403_count": int(((statuses != 403) & (~statuses.between(200, 299))).sum()),
    }


def build_comparable_benchmark(results: list) -> pd.DataFrame:
    """
    Builds a per-family + ALL comparable benchmark DataFrame contrasting:
    - WAFBench 3-Tier (DR, BR, FPR_D, FPR_B on VALID records)
    - HTTP-Status-Only (Blocking BR & FPR_B purely from HTTP 403)
    - Noise counts caught by Validity Oracle (I_UNATTRIBUTED, I_BASELINE_CONFLICT, E_CORRELATION)
    """
    df = pd.DataFrame(results)
    if df.empty:
        return pd.DataFrame()

    families = sorted(df["family"].dropna().unique().tolist()) + ["ALL"]
    rows = []
    for fam in families:
        sub = results if fam == "ALL" else [r for r in results if r.get("family") == fam]
        wb = calculate_metrics(sub)
        hs = calculate_http_status_only_metrics(sub)
        wb_br = wb.get("blocking_rate")
        hs_br = hs.get("http_only_blocking_rate")
        br_delta = round(hs_br - wb_br, 2) if (wb_br is not None and hs_br is not None) else None

        rows.append({
            "family": fam,
            "wafbench_valid_runs": wb.get("valid", 0),
            "wafbench_DR_pct": wb.get("detection_rate"),
            "wafbench_BR_pct": wb_br,
            "wafbench_FPR_D_pct": wb.get("detection_fpr"),
            "wafbench_FPR_B_pct": wb.get("blocking_fpr"),
            "http_only_BR_pct": hs_br,
            "http_only_FPR_B_pct": hs.get("http_only_blocking_fpr"),
            "br_inflation_delta_pct": br_delta,
            "noise_I_UNATTRIBUTED": hs.get("unattributed_noise", 0),
            "noise_I_BASELINE_CONFLICT": hs.get("baseline_conflict_noise", 0),
            "noise_E_CORRELATION": hs.get("correlation_error_noise", 0),
        })
    return pd.DataFrame(rows)


def summarize(results: list) -> pd.DataFrame:
    """One row per (state, family) plus an ALL row per state."""
    df = pd.DataFrame(results)
    rows = []
    for state in df["state"].unique():
        sdf = df[df["state"] == state]
        for family in list(sdf["family"].unique()) + ["ALL"]:
            part = sdf if family == "ALL" else sdf[sdf["family"] == family]
            valid = part[part["validity"] == "VALID"]
            cells = valid["metric_cell"].value_counts().to_dict()
            row = {
                "state": state,
                "family": family,
                "attempted": len(part),
                "valid": len(valid),
                "invalid": int(part["validity"].astype(str).str.startswith("E_").sum()),
                "inconclusive": int(part["validity"].astype(str).str.startswith("I_").sum()),
                "backend_effect": int(part["backend_effect"].sum()),
            }
            for k in ("TP", "FN", "FP", "TN"):
                row[k] = int(sum(v for cell, v in cells.items() if str(cell).startswith(k + "_")))
            row["rate"] = _rate(row["TP"], row["TP"] + row["FN"])
            row["fpr"] = _rate(row["FP"], row["FP"] + row["TN"])
            rows.append(row)
    return pd.DataFrame(rows)


def export_csv(results: list, output_path: str):
    df = pd.DataFrame(results)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Exported results matrix to: {output_path}")


def export_summary_csv(results: list, output_path: str) -> pd.DataFrame:
    summary = summarize(results)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    summary.to_csv(output_path, index=False)
    print(f"[+] Exported summary to: {output_path}")
    return summary


def export_comparable_benchmark_csv(results: list, output_path: str) -> pd.DataFrame:
    comp = build_comparable_benchmark(results)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    comp.to_csv(output_path, index=False)
    print(f"[+] Exported comparable benchmark to: {output_path}")
    return comp


def print_summary(metrics: dict, summary: pd.DataFrame, latency: dict = None):
    print("\n" + "=" * 70)
    print("Per state / family (rate = DR or BR, fpr = FPR_D or FPR_B)")
    print(summary.to_string(index=False))
    print("-" * 70)
    fmt = lambda v: "n/a" if v is None else f"{v}%"
    print(f"DR    = {fmt(metrics.get('detection_rate'))}   (TP_D {metrics.get('tp_d')} / FN_D {metrics.get('fn_d')})")
    print(f"BR    = {fmt(metrics.get('blocking_rate'))}   (TP_B {metrics.get('tp_b')} / FN_B {metrics.get('fn_b')})")
    print(f"FPR_D = {fmt(metrics.get('detection_fpr'))}   (FP_D {metrics.get('fp_d')} / TN_D {metrics.get('tn_d')})")
    print(f"FPR_B = {fmt(metrics.get('blocking_fpr'))}   (FP_B {metrics.get('fp_b')} / TN_B {metrics.get('tn_b')})")
    print(f"WAF runs: attempted {metrics.get('attempted')}, valid {metrics.get('valid')}, "
          f"invalid {metrics.get('invalid')}, inconclusive {metrics.get('inconclusive')}, "
          f"flaky (case, state) {metrics.get('flaky_pairs')}")
    if latency:
        print("-" * 70)
        for state, st in latency.get("states", {}).items():
            extra = f", overhead p50 {st['overhead_p50_ms']:.1f} ms" if st.get("overhead_p50_ms") is not None else ""
            print(f"Latency {state:<14} p50 {st['p50_ms']:.1f} ms, p95 {st['p95_ms']:.1f} ms{extra}")
        if latency.get("reset_count"):
            print(f"Fixture reset   p50 {latency['reset_p50_ms']:.1f} ms, max {latency['reset_max_ms']:.1f} ms")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="WAFBench Metrics & Comparable Benchmark Reporter")
    parser.add_argument("--from-db", action="store_true", help="Load correlated events from PostgreSQL event-db")
    parser.add_argument("--from-csv", type=str, help="Load results from an existing CSV file")
    parser.add_argument("--batch-id", type=str, default=None, help="Filter or label batch_id")
    parser.add_argument("--run-id", type=str, default=None, help="Filter by run_id when reading from DB")
    parser.add_argument("--config-rev", type=str, default="C0", help="Config revision label (C0 or C1)")
    parser.add_argument("--save-db", action="store_true", help="Insert computed metrics into evaluation_metrics table")
    parser.add_argument("--out-dir", type=str, default="runner/results", help="Output directory for CSV reports")
    args = parser.parse_args()

    if args.from_db:
        results = load_events_from_db(batch_id=args.batch_id, run_id=args.run_id)
    elif args.from_csv:
        results = pd.read_csv(args.from_csv).to_dict(orient="records")
    else:
        parser.error("Specify either --from-db or --from-csv <path>.")

    if not results:
        print("[!] No records found matching query.")
        return

    metrics = calculate_metrics(results)
    summary = export_summary_csv(results, os.path.join(args.out_dir, "summary_report.csv"))
    comp = export_comparable_benchmark_csv(results, os.path.join(args.out_dir, "comparable_benchmark.csv"))
    print_summary(metrics, summary)
    print("\nComparable Benchmark (WAFBench 3-Tier vs HTTP-Status-Only):")
    print(comp.to_string(index=False))

    if args.save_db:
        bid = args.batch_id or results[0].get("batch_id") or "manual_batch"
        save_metrics_to_db(metrics, batch_id=bid, config_revision=args.config_rev)


if __name__ == "__main__":
    main()
