#!/usr/bin/env python3
"""
Test Harness Request Manager: Connection pool, UUIDv4 correlation IDs, SHA256 fingerprints.
Author: Kieu Dang Vuong
"""

import requests
import uuid
import hashlib
import json

class RequestManager:
    def __init__(self, timeout: float = 5.0):
        self.session = requests.Session()
        self.timeout = timeout

    def send_request(self, target_base_url: str, case_data: dict, correlation_id: str = None) -> dict:
        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        endpoint = case_data.get("endpoint", "")
        method = case_data.get("method", "GET").upper()
        raw_body = case_data.get("body", "")

        # Prepare headers
        headers = {}
        for k, v in case_data.get("headers", {}).items():
            val = v.replace("{correlation_id}", correlation_id)
            val = val.replace("{host}", target_base_url.replace("http://", "").replace("https://", ""))
            headers[k] = val
        headers["X-Request-ID"] = correlation_id

        # Calculate payload fingerprint
        request_sha256 = hashlib.sha256(raw_body.encode("utf-8") if raw_body else endpoint.encode("utf-8")).hexdigest()

        full_url = f"{target_base_url}{endpoint}"

        try:
            resp = self.session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=raw_body.encode("utf-8") if raw_body else None,
                timeout=self.timeout
            )
            return {
                "success": True,
                "correlation_id": correlation_id,
                "request_sha256": request_sha256,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text,
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "correlation_id": correlation_id,
                "request_sha256": request_sha256,
                "status_code": None,
                "headers": {},
                "text": "",
                "error": str(e)
            }
