#!/usr/bin/env python3
"""
Metrics Calculation and Report Generation (Table 5.2 & 5.3)
Author: Kieu Dang Vuong
"""

import pandas as pd
import os

def calculate_metrics(results: list) -> dict:
    df = pd.DataFrame(results)
    if df.empty:
        return {}

    valid_df = df[df["validity"] == "VALID"]
    
    # 1. Detection Rate (DR) in DetectionOnly
    det_malicious = valid_df[(valid_df["state"] == "DetectionOnly") & (valid_df["label"] == "malicious")]
    tp_d = len(det_malicious[det_malicious["metric_cell"] == "TP_D"])
    fn_d = len(det_malicious[det_malicious["metric_cell"] == "FN_D"])
    dr = (tp_d / (tp_d + fn_d) * 100) if (tp_d + fn_d) > 0 else None

    # 2. Blocking Rate (BR) in Blocking
    block_malicious = valid_df[(valid_df["state"] == "Blocking") & (valid_df["label"] == "malicious")]
    tp_b = len(block_malicious[block_malicious["metric_cell"] == "TP_B"])
    fn_b = len(block_malicious[block_malicious["metric_cell"] == "FN_B"])
    br = (tp_b / (tp_b + fn_b) * 100) if (tp_b + fn_b) > 0 else None

    # 3. Detection False Positive Rate (FPR_D)
    det_benign = valid_df[(valid_df["state"] == "DetectionOnly") & (valid_df["label"].isin(["benign", "edge"]))]
    fp_d = len(det_benign[det_benign["metric_cell"] == "FP_D"])
    tn_d = len(det_benign[det_benign["metric_cell"] == "TN_D"])
    fpr_d = (fp_d / (fp_d + tn_d) * 100) if (fp_d + tn_d) > 0 else None

    # 4. Blocking False Positive Rate (FPR_B)
    block_benign = valid_df[(valid_df["state"] == "Blocking") & (valid_df["label"].isin(["benign", "edge"]))]
    fp_b = len(block_benign[block_benign["metric_cell"] == "FP_B"])
    tn_b = len(block_benign[block_benign["metric_cell"] == "TN_B"])
    fpr_b = (fp_b / (fp_b + tn_b) * 100) if (fp_b + tn_b) > 0 else None

    return {
        "total_executions": len(df),
        "total_valid": len(valid_df),
        "tp_d": tp_d, "fn_d": fn_d, "detection_rate": dr,
        "tp_b": tp_b, "fn_b": fn_b, "blocking_rate": br,
        "fp_d": fp_d, "tn_d": tn_d, "detection_fpr": fpr_d,
        "fp_b": fp_b, "tn_b": tn_b, "blocking_fpr": fpr_b
    }

def export_csv(results: list, output_path: str):
    df = pd.DataFrame(results)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Exported results matrix to: {output_path}")
