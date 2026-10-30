#!/usr/bin/env python3
"""
Corpus Validator: Validates test case syntax, contract consistency,
and required malicious/benign pairing.
Author: Tran Quoc Bao
"""

import os
import json
import sys

ALLOWED_ENDPOINTS = ["/login", "/search", "/file", "/fetch"]
ALLOWED_LABELS = ["malicious", "benign", "edge"]

def validate_corpus():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")
    
    cases = []
    for root, _, files in os.walk(cases_dir):
        for file in files:
            if file.endswith(".json"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        data["_file"] = full_path
                        cases.append(data)
                except Exception as e:
                    print(f"[!] Lỗi đọc file {full_path}: {e}")
                    return False

    errors = 0
    case_ids = set()

    for c in cases:
        cid = c.get("case_id")
        if not cid:
            print(f"[!] Thiếu case_id trong {c['_file']}")
            errors += 1
            continue
        if cid in case_ids:
            print(f"[!] Trùng lặp case_id: {cid}")
            errors += 1
        case_ids.add(cid)

        # Kiểm tra Label
        if c.get("label") not in ALLOWED_LABELS:
            print(f"[!] Invalid label '{c.get('label')}' in {cid}")
            errors += 1

        # Kiểm tra Endpoint
        endpoint = c.get("endpoint", "")
        base_ep = endpoint.split("?")[0]
        if base_ep not in ALLOWED_ENDPOINTS:
            print(f"[!] Invalid endpoint '{base_ep}' in {cid}")
            errors += 1

        # Kiểm tra Headers
        headers = c.get("headers", {})
        if "X-Request-ID" not in headers or headers["X-Request-ID"] != "{correlation_id}":
            print(f"[!] {cid}: Thiếu header X-Request-ID hoặc placeholder không đúng")
            errors += 1
        if "Host" not in headers or headers["Host"] != "{host}":
            print(f"[!] {cid}: Thiếu header Host hoặc placeholder không đúng")
            errors += 1

        # Kiểm tra POST body JSON
        if c.get("method") == "POST":
            if headers.get("Content-Type") != "application/json":
                print(f"[!] {cid}: POST request phải có Content-Type: application/json")
                errors += 1
            try:
                json.loads(c.get("body", "{}"))
            except Exception:
                print(f"[!] {cid}: Body không phải JSON hợp lệ")
                errors += 1

    # Kiểm tra cặp đối chứng (Paired benign contrast)
    malicious_ids = [c["case_id"] for c in cases if c["label"] == "malicious"]
    for mid in malicious_ids:
        paired_benign = f"{mid}-B1"
        if paired_benign not in case_ids:
            print(f"[!] Cảnh báo: Test case tấn công {mid} thiếu case đối chứng {paired_benign}")
            errors += 1

    if errors == 0:
        print(f"[OK] All {len(cases)} test cases passed validation checks!")
        return True
    else:
        print(f"[FAIL] Detected {errors} validation errors!")
        return False

if __name__ == "__main__":
    success = validate_corpus()
    sys.exit(0 if success else 1)
