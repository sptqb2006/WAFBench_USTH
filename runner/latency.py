#!/usr/bin/env python3
"""
Latency Profiling and Baseline Gate Validator
Author: Kieu Dang Vuong
"""

import time

class LatencyProfiler:
    def __init__(self):
        self.reset_times = []
        self.request_latencies = []

    def record_reset(self, duration_ms: float):
        self.reset_times.append(duration_ms)
        # Baseline Gate: Reset must be <= 5000 ms (5 seconds)
        if duration_ms > 5000:
            print(f"[!] Warning: Fixture reset took {duration_ms:.1f}ms (> 5.0s threshold)")

    def record_request(self, duration_ms: float):
        self.request_latencies.append(duration_ms)

    def summary(self) -> dict:
        avg_reset = sum(self.reset_times) / len(self.reset_times) if self.reset_times else 0
        avg_lat = sum(self.request_latencies) / len(self.request_latencies) if self.request_latencies else 0
        return {
            "avg_reset_duration_ms": avg_reset,
            "avg_request_latency_ms": avg_lat,
            "total_requests": len(self.request_latencies)
        }
