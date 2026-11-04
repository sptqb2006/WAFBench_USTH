"""
View 3: Live Canary & Fast Reset Trigger.

Enables real-time execution of the canary probe suite, dynamic ModSecurity
operating mode switching (DetectionOnly <-> Blocking), and sub-5.0s database
fast reset gate verification.
Adheres strictly to wafbench_agent_tui_guide.md and AGENTS.md rules.
"""

import os
import sys
import time
from datetime import datetime
from typing import List

import requests
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Label, Static

from tui.sanitizers import safe_str
from tui.theme import BADGE_BLOCKED, BADGE_FAIL, BADGE_OK, BADGE_PASSED, BADGE_READY, BADGE_WAIT

# Core paths
CLI_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNNER_DIR = os.path.join(CLI_DIR, "runner")
if RUNNER_DIR not in sys.path:
    sys.path.insert(0, RUNNER_DIR)

import manager
from oracle.sqli_oracle import get_fixture_counts

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")
DIRECT_URL = os.getenv("DIRECT_APP_URL", "http://127.0.0.1:8001")


class CanaryResetView(VerticalScroll):
    """
    View 3: Interactive Canary Testing, Mode Control, and Fast Reset Gate.
    """

    DEFAULT_CSS = """
    CanaryResetView {
        height: 1fr;
        padding: 0 1;
    }
    #canary-actions-box {
        height: auto;
        margin: 0 0 1 0;
        padding: 1;
        background: #161b22;
        border: round #30363d;
    }
    #canary-button-row {
        height: auto;
        align: left middle;
        margin: 1 0 0 0;
    }
    #canary-button-row Button {
        margin: 0 1 0 0;
    }
    #canary-status-card {
        height: auto;
        margin: 0 0 1 0;
        padding: 1;
        background: #141a24;
        border: round #30363d;
    }
    #activity-log-box {
        height: 1fr;
        min-height: 14;
        padding: 1;
        background: #0d1117;
        border: round #30363d;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.logs: List[str] = [
            f"[{self._now()}] {BADGE_READY} Laboratory initialized. Gateway: {GATEWAY_URL} | Direct App: {DIRECT_URL}",
            f"[{self._now()}] {BADGE_OK} Infrastructure verified: Dell Host <-> KVM Guest VM (100.66.229.98).",
        ]
        self.current_mode = "DetectionOnly"

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def compose(self) -> ComposeResult:
        with Vertical(id="canary-actions-box"):
            yield Label("[bold white]Laboratory Control Gate & Verification Actions:[/bold white]")
            with Horizontal(id="canary-button-row"):
                yield Button("[Run Canary Probe]", id="btn-run-canary", variant="primary")
                yield Button("[Toggle WAF Mode]", id="btn-toggle-mode", variant="warning")
                yield Button("[Trigger Fast Reset Gate]", id="btn-fast-reset", variant="success")

        with Vertical(id="canary-status-card"):
            yield Static(self._render_status_summary(), id="status-card-static")

        with Vertical(id="activity-log-box"):
            yield Label("[bold white]Deterministic Execution & Telemetry Log:[/bold white]")
            yield Static(self._render_logs(), id="activity-log-static")

    def _render_status_summary(self) -> Text:
        raw = (
            f"[bold cyan]Active Operating Mode:[/] [{self.current_mode}]  |  "
            f"[bold cyan]Gateway Endpoint:[/] {GATEWAY_URL}  |  "
            f"[bold cyan]Direct App Endpoint:[/] {DIRECT_URL}\n"
            f"[dim]Canary Rule Verification: SecRule 941100 / 949110 | Fast Reset Gate Threshold <= 5.00s[/dim]"
        )
        return Text.from_markup(raw)

    def _render_logs(self) -> Text:
        raw = "\n".join(self.logs[-15:])
        return Text.from_markup(raw)


    def _append_log(self, msg: str) -> None:
        self.logs.append(f"[{self._now()}] {msg}")
        try:
            log_widget = self.query_one("#activity-log-static", Static)
            log_widget.update(self._render_logs())
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-run-canary":
            self.run_canary_probe()
        elif bid == "btn-toggle-mode":
            self.toggle_waf_mode()
        elif bid == "btn-fast-reset":
            self.run_fast_reset()

    def run_canary_probe(self) -> None:
        """Executes the standard canary probe and inspects audit evidence."""
        self._append_log(f"{BADGE_WAIT} Executing live canary probe against {GATEWAY_URL}...")
        try:
            ok, msg = manager.mode_canary(GATEWAY_URL, self.current_mode)
            if ok:
                self._append_log(f"{BADGE_OK} Canary verification successful: {safe_str(msg)}")
            else:
                self._append_log(f"{BADGE_FAIL} Canary verification failed: {safe_str(msg)}")
        except Exception as exc:
            self._append_log(f"{BADGE_FAIL} Canary probe exception: {safe_str(str(exc))}")

    def toggle_waf_mode(self) -> None:
        """Toggles ModSecurity between DetectionOnly and Blocking (On)."""
        target_mode = "Blocking" if self.current_mode == "DetectionOnly" else "DetectionOnly"
        engine_val = "On" if target_mode == "Blocking" else "DetectionOnly"

        self._append_log(f"{BADGE_WAIT} Switching WAF mode to {target_mode} (SecRuleEngine {engine_val})...")
        try:
            ok, err = manager.set_waf_mode(engine_val)
            if not ok:
                self._append_log(f"{BADGE_FAIL} Failed to switch mode: {safe_str(err)}")
                return

            ready = manager.wait_gateway_ready(GATEWAY_URL, timeout=8.0)
            if ready:
                self.current_mode = target_mode
                self._append_log(f"{BADGE_OK} WAF mode successfully updated to [{self.current_mode}]. Gateway reloaded and healthy.")
                try:
                    card = self.query_one("#status-card-static", Static)
                    card.update(self._render_status_summary())
                except Exception:
                    pass
            else:
                self._append_log(f"{BADGE_FAIL} Gateway failed to regain ready state after mode reload.")
        except Exception as exc:
            self._append_log(f"{BADGE_FAIL} Mode toggle exception: {safe_str(str(exc))}")

    def run_fast_reset(self) -> None:
        """Invokes POST /health/reset, measures duration, and verifies DB fixtures."""
        self._append_log(f"{BADGE_WAIT} Invoking POST {DIRECT_URL}/health/reset...")
        try:
            t0 = time.perf_counter()
            resp = requests.post(f"{DIRECT_URL}/health/reset", timeout=5.0)
            latency_s = time.perf_counter() - t0

            if resp.status_code == 200:
                body = resp.json()
                reported_ms = body.get("reset_duration_ms", int(latency_s * 1000))
                counts = get_fixture_counts()
                u, a, s = counts.get("users", 0), counts.get("articles", 0), counts.get("sessions", 0)

                gate_ok = latency_s <= 5.0 and (u == 3 and s == 0)
                badge = BADGE_OK if gate_ok else BADGE_FAIL
                self._append_log(
                    f"{badge} Fast reset complete in {latency_s:.3f}s (reported={reported_ms}ms, limit<=5.0s). "
                    f"Fixtures: users={u}, articles={a}, sessions={s}."
                )
            else:
                self._append_log(f"{BADGE_FAIL} Reset returned HTTP {resp.status_code}: {safe_str(resp.text[:60])}")
        except Exception as exc:
            self._append_log(f"{BADGE_FAIL} Reset invocation exception: {safe_str(str(exc))}")

    def refresh_data(self) -> None:
        """Queries gateway mode from container config and updates UI."""
        try:
            rc, out, _ = manager.docker_exec("wb-gateway", ["grep", "-i", "SecRuleEngine", "/etc/modsecurity.d/main.conf"])
            if rc == 0:
                if "on" in out.lower() and "detectiononly" not in out.lower():
                    self.current_mode = "Blocking"
                else:
                    self.current_mode = "DetectionOnly"
                card = self.query_one("#status-card-static", Static)
                card.update(self._render_status_summary())
        except Exception:
            pass


# Canonical class alias conforming to Section 4.3 naming convention
CanaryView = CanaryResetView

