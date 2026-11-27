#!/usr/bin/env python3
"""
Metrics Calculation and Report Generation (Table 5.2 & 5.3)
Baseline Gate, flaky detection, detailed and summary CSV.
Author: Kieu Dang Vuong
"""

import os

import pandas as pd

BENIGN_LABELS = ("benign", "edge")


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
    valid = waf[waf["validity"] == "VALID"]
    count = valid["metric_cell"].value_counts().to_dict()
    c = {k: int(count.get(k, 0)) for k in ("TP_D", "FN_D", "FP_D", "TN_D", "TP_B", "FN_B", "FP_B", "TN_B")}

    return {
        "attempted": len(waf),
        "valid": len(valid),
        "invalid": int(waf["validity"].str.startswith("E_").sum()),
        "inconclusive": int(waf["validity"].str.startswith("I_").sum()),
        **{k.lower(): v for k, v in c.items()},
        "detection_rate": _rate(c["TP_D"], c["TP_D"] + c["FN_D"]),
        "blocking_rate": _rate(c["TP_B"], c["TP_B"] + c["FN_B"]),
        "detection_fpr": _rate(c["FP_D"], c["FP_D"] + c["TN_D"]),
        "blocking_fpr": _rate(c["FP_B"], c["FP_B"] + c["TN_B"]),
        "flaky_pairs": int(df[df["flaky"]][["case_id", "state"]].drop_duplicates().shape[0]) if "flaky" in df else 0,
    }


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
                "invalid": int(part["validity"].str.startswith("E_").sum()),
                "inconclusive": int(part["validity"].str.startswith("I_").sum()),
                "backend_effect": int(part["backend_effect"].sum()),
            }
            for k in ("TP", "FN", "FP", "TN"):
                row[k] = int(sum(v for cell, v in cells.items() if cell.startswith(k + "_")))
            row["rate"] = _rate(row["TP"], row["TP"] + row["FN"])
            row["fpr"] = _rate(row["FP"], row["FP"] + row["TN"])
            rows.append(row)
    return pd.DataFrame(rows)


def export_csv(results: list, output_path: str):
    df = pd.DataFrame(results)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Exported results matrix to: {output_path}")


def export_summary_csv(results: list, output_path: str) -> pd.DataFrame:
    summary = summarize(results)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    summary.to_csv(output_path, index=False)
    print(f"[+] Exported summary to: {output_path}")
    return summary


def print_summary(metrics: dict, summary: pd.DataFrame, latency: dict):
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
    print("-" * 70)
    for state, st in latency.get("states", {}).items():
        extra = f", overhead p50 {st['overhead_p50_ms']:.1f} ms" if st.get("overhead_p50_ms") is not None else ""
        print(f"Latency {state:<14} p50 {st['p50_ms']:.1f} ms, p95 {st['p95_ms']:.1f} ms{extra}")
    if latency.get("reset_count"):
        print(f"Fixture reset   p50 {latency['reset_p50_ms']:.1f} ms, max {latency['reset_max_ms']:.1f} ms")
    print("=" * 70)
