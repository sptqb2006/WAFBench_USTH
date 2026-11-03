#!/usr/bin/env python3
"""
Latency Profiling: request latency per state and fixture reset duration
Author: Kieu Dang Vuong
"""

RESET_LIMIT_MS = 5000


def percentile(values: list, p: float):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


class LatencyProfiler:
    def __init__(self):
        self.reset_times = []
        self.request_latencies = {}

    def record_reset(self, duration_ms: float):
        self.reset_times.append(duration_ms)
        if duration_ms > RESET_LIMIT_MS:
            print(f"[!] Warning: Fixture reset took {duration_ms:.1f}ms (> {RESET_LIMIT_MS}ms limit)")

    def record_request(self, state: str, duration_ms: float):
        if duration_ms is not None:
            self.request_latencies.setdefault(state, []).append(duration_ms)

    def summary(self) -> dict:
        out = {
            "reset_count": len(self.reset_times),
            "reset_p50_ms": percentile(self.reset_times, 50),
            "reset_max_ms": max(self.reset_times) if self.reset_times else None,
            "states": {},
        }
        for state, vals in self.request_latencies.items():
            out["states"][state] = {
                "count": len(vals),
                "p50_ms": percentile(vals, 50),
                "p95_ms": percentile(vals, 95),
            }
        direct = out["states"].get("Direct-to-App", {}).get("p50_ms")
        for state, st in out["states"].items():
            st["overhead_p50_ms"] = (st["p50_ms"] - direct) if direct is not None and state != "Direct-to-App" else None
        return out
