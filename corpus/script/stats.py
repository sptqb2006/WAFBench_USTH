#!/usr/bin/env python3
"""
Corpus Stats: Summarizes test case counts, vulnerability families, and label distributions.
Author: Tran Quoc Bao
"""

import os
import json
from collections import Counter

def show_stats():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")

    cases = []
    for root, _, files in os.walk(cases_dir):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                    cases.append(json.load(f))

    print("=" * 60)
    print("           WAFBench Test Corpus Statistics")
    print("=" * 60)
    print(f"Tổng số test cases: {len(cases)}")
    
    label_counts = Counter(c.get("label") for c in cases)
    print("\n[ Phân bổ theo Nhãn (Label) ]")
    for label, count in label_counts.items():
        print(f"  • {label:<12}: {count:>3} cases ({count/len(cases)*100:.1f}%)")

    family_counts = Counter(c.get("family") for c in cases)
    print("\n[ Phân bổ theo Nhóm Lỗ hổng (Attack Family) ]")
    for fam, count in family_counts.items():
        print(f"  • {fam:<16}: {count:>3} cases")

    print("=" * 60)

if __name__ == "__main__":
    show_stats()
