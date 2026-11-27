#!/usr/bin/env python3
"""
Corpus Stats: Summarizes test case counts, directory distribution,
vulnerability families, and label breakdowns (including Holdout Suite).
Author: Tran Quoc Bao
"""

import os
import json
from collections import Counter

def show_stats():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")

    cases = []
    dir_counts = Counter()

    for root, _, files in os.walk(cases_dir):
        rel_dir = os.path.relpath(root, cases_dir)
        for file in files:
            if file.endswith(".json"):
                full_path = os.path.join(root, file)
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    data["_dir"] = rel_dir
                    cases.append(data)
                    dir_counts[rel_dir] += 1

    total = len(cases)
    print("=" * 65)
    print("           WAFBench Test Corpus Comprehensive Statistics")
    print("=" * 65)
    print(f"Total test cases: {total}")

    print("\n[ 1. Distribution by Storage Directory ]")
    for d, count in sorted(dir_counts.items()):
        print(f"  • cases/{d:<15}: {count:>3} cases ({count/total*100:.1f}%)")

    label_counts = Counter(c.get("label") for c in cases)
    print("\n[ 2. Distribution by Label ]")
    for label in ["malicious", "benign", "edge"]:
        count = label_counts.get(label, 0)
        print(f"  • {label:<15}: {count:>3} cases ({count/total*100:.1f}%)")

    family_counts = Counter(c.get("family") for c in cases)
    print("\n[ 3. Distribution by Vulnerability Family ]")
    for fam in ["SQL Injection", "Reflected XSS", "Path Traversal", "SSRF"]:
        count = family_counts.get(fam, 0)
        print(f"  • {fam:<17}: {count:>3} cases ({count/total*100:.1f}%)")

    # Holdout suite details
    holdout_cases = [c for c in cases if c.get("_dir") == "holdout"]
    print("\n[ 4. Holdout Regression Suite Details (Reserved for RPR) ]")
    print(f"  • Total holdout cases: {len(holdout_cases)}")
    holdout_labels = Counter(c.get("label") for c in holdout_cases)
    for lbl, cnt in holdout_labels.items():
        print(f"    - {lbl:<12}: {cnt} cases")
    print("=" * 65)

if __name__ == "__main__":
    show_stats()
