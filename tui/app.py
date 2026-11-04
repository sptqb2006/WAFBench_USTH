"""
WAFBench Full-Screen Interactive Terminal User Interface (Textual Mode).

Adheres strictly to document/wafbench_agent_tui_guide.md (Sections 2.1, 4.3)
and AGENTS.md rules:
- Academic ANSI theme, zero emojis, zero pictographs.
- Zero placeholders: domain-grounded fallbacks only.
- Raw payloads escaped with rich.markup.escape (zero HTML leaks).
- Clean OpenSSH headless execution support.
"""

import argparse
import asyncio
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict

# Ensure repository root and runner directory are in sys.path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(APP_DIR)
RUNNER_DIR = os.path.join(REPO_ROOT, "runner")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if RUNNER_DIR not in sys.path:
    sys.path.insert(0, RUNNER_DIR)

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.widgets import ContentSwitcher, Footer, Static

import manager
from tui.renderables import build_lab_header
from tui.sanitizers import safe_str
from tui.theme import DEFAULT_BOX, WAFBENCH_THEME
from tui.views.canary import CanaryResetView
from tui.views.exclusions import RuleExclusionView
from tui.views.inspector import EvidenceInspectorView
from tui.views.matrix import OverviewMatrixView

VIEW_NAMES = {
    "view1": "View 1: Overview & 3-State Matrix",
    "view2": "View 2: 3-Tier Evidence Inspector",
    "view3": "View 3: Live Canary & Fast Reset Trigger",
    "view4": "View 4: C0 vs C1 Rule Exclusion View",
}


class WAFBenchTUI(App[None]):
    """
    WAFBench Full-Screen Academic Interactive Console.
    Orchestrates the 4 evaluation views, real-time Docker/ModSecurity telemetry,
    and OpenSSH-safe deterministic presentation.
    """

    TITLE = "WAFBench Empirical Evaluation Laboratory"
    SUB_TITLE = "Nginx 1.26 / ModSec v3 / CRS v4.0.0"

    BINDINGS = [
        Binding("1", "switch_view('view1')", "[1] Overview & Matrix", priority=True),
        Binding("2", "switch_view('view2')", "[2] Evidence Inspector", priority=True),
        Binding("3", "switch_view('view3')", "[3] Canary & Reset", priority=True),
        Binding("4", "switch_view('view4')", "[4] C0 vs C1 Exclusions", priority=True),
        Binding("r", "refresh_status", "[R] Refresh", priority=True),
        Binding("q", "clean_quit", "[Q] Quit", priority=True),
    ]

    CSS = """
    Screen {
        background: #0d1117;
        color: #e6edf3;
        layout: vertical;
    }

    #lab-header-widget {
        height: auto;
        dock: top;
        margin: 0;
        padding: 0;
        border: none;
    }

    #content-container {
        height: 1fr;
        margin: 0 1;
        padding: 0;
        border: round #30363d;
        background: #161b22;
    }

    #status-bar-widget {
        dock: bottom;
        height: 1;
        background: #161b22;
        color: #8b949e;
        content-align: center middle;
        border-top: solid #30363d;
    }

    Footer {
        dock: bottom;
        height: 1;
        background: #0d1117;
        color: #8b949e;
    }

    OverviewMatrixView, EvidenceInspectorView, CanaryResetView, RuleExclusionView {
        height: 1fr;
        padding: 0 1;
    }
    """

    def __init__(self, initial_view: str = "view1", ascii_only: bool = False, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.initial_view = initial_view
        self.ascii_only = ascii_only
        self.stack_status: Dict[str, bool] = {
            "wb-gateway": False,
            "wb-app": False,
            "wb-app-db": False,
            "wb-mock": False,
            "wb-telemetry": False,
            "wb-event-db": False,
            "wb-dashboard": False,
        }
        self.policy_meta: Dict[str, str] = {
            "mode": "DetectionOnly",
            "revision": "C0",
            "paranoia_level": "1",
            "inbound_threshold": "5",
            "transport": "SSH Tunnel (100.66.229.98)",
        }

    def on_mount(self) -> None:
        """App initialization hook."""
        self.console.push_theme(WAFBENCH_THEME)
        self.refresh_telemetry_status()

    def compose(self) -> ComposeResult:
        """Constructs layout: Header -> Content Container -> Status Bar -> Footer."""
        yield Static(
            build_lab_header(self.stack_status, self.policy_meta),
            id="lab-header-widget",
        )

        with Container(id="content-container"):
            with ContentSwitcher(initial=self.initial_view, id="view-switcher"):
                yield OverviewMatrixView(id="view1")
                yield EvidenceInspectorView(id="view2")
                yield CanaryResetView(id="view3")
                yield RuleExclusionView(id="view4")

        yield Static(self._format_status_bar(self.initial_view), id="status-bar-widget")
        yield Footer()

    def _format_status_bar(self, active_view_id: str, extra_msg: str = "") -> str:
        view_title = VIEW_NAMES.get(active_view_id, active_view_id)
        msg_suffix = f"  |  [yellow]{safe_str(extra_msg)}[/yellow]" if extra_msg else ""
        return (
            f"[bold cyan]ACTIVE VIEW:[/] [bold white]{view_title}[/]  |  "
            f"[dim]Keys: [1-4] Switch Views | [R] Refresh | [Q] Quit[/dim]{msg_suffix}"
        )

    def action_switch_view(self, view_id: str) -> None:
        """Switches active view inside ContentSwitcher."""
        try:
            switcher = self.query_one("#view-switcher", ContentSwitcher)
            switcher.current = view_id
            status_bar = self.query_one("#status-bar-widget", Static)
            status_bar.update(self._format_status_bar(view_id))
        except Exception:
            pass

    def action_clean_quit(self) -> None:
        """Exits cleanly back to terminal."""
        self.exit()

    def action_refresh_status(self) -> None:
        """Triggers manual telemetry and container refresh."""
        now_str = datetime.now().strftime("%H:%M:%S")
        self.refresh_telemetry_status()

        # Update active view
        try:
            switcher = self.query_one("#view-switcher", ContentSwitcher)
            cur = switcher.current
            if cur:
                active_widget = self.query_one(f"#{cur}")
                if hasattr(active_widget, "refresh_data"):
                    active_widget.refresh_data()
            status_bar = self.query_one("#status-bar-widget", Static)
            status_bar.update(self._format_status_bar(cur or "view1", f"Telemetry refreshed at {now_str}"))
        except Exception:
            pass

    def refresh_telemetry_status(self) -> None:
        """Queries Docker/HTTP health status for the 7 microservices."""
        services = ["wb-gateway", "wb-app", "wb-app-db", "wb-mock", "wb-telemetry", "wb-event-db", "wb-dashboard"]
        try:
            p = manager._run_docker_cmd(["docker", "ps", "--format", "{{.Names}}"])
            running_names = set(p.stdout.decode().splitlines()) if p.returncode == 0 else set()
            for svc in services:
                self.stack_status[svc] = svc in running_names
        except Exception:
            for svc in services:
                self.stack_status[svc] = False

        # Query ModSecurity engine mode
        try:
            rc, out, _ = manager.docker_exec("wb-gateway", ["grep", "-i", "SecRuleEngine", "/etc/modsecurity.d/main.conf"])
            if rc == 0:
                if "on" in out.lower() and "detectiononly" not in out.lower():
                    self.policy_meta["mode"] = "Blocking"
                else:
                    self.policy_meta["mode"] = "DetectionOnly"
        except Exception:
            pass

        # Update lab header renderable
        try:
            header_widget = self.query_one("#lab-header-widget", Static)
            header_widget.update(build_lab_header(self.stack_status, self.policy_meta))
        except Exception:
            pass


def query_system_state() -> tuple[Dict[str, bool], Dict[str, str]]:
    """Gathers container readiness and ModSecurity engine configuration."""
    services = [
        "wb-gateway",
        "wb-app",
        "wb-app-db",
        "wb-mock",
        "wb-telemetry",
        "wb-event-db",
        "wb-dashboard",
    ]
    stack_status = {svc: False for svc in services}
    policy_meta = {
        "mode": "DetectionOnly",
        "revision": "C0",
        "anomaly_threshold": "5",
        "transport": "SSH Tunnel" if not os.path.exists("/home/webadmin/WAFBench_USTH") else "Direct Local",
    }
    try:
        p = manager._run_docker_cmd(["docker", "ps", "--format", "{{.Names}}"])
        running = set(p.stdout.decode().splitlines()) if p.returncode == 0 else set()
        for svc in services:
            stack_status[svc] = svc in running
    except Exception:
        pass

    try:
        rc, out, _ = manager.docker_exec("wb-gateway", ["grep", "-i", "SecRuleEngine", "/etc/modsecurity.d/main.conf"])
        if rc == 0:
            if "on" in out.lower() and "detectiononly" not in out.lower():
                policy_meta["mode"] = "Blocking"
            else:
                policy_meta["mode"] = "DetectionOnly"
    except Exception:
        pass

    return stack_status, policy_meta



def main() -> None:
    """CLI entrypoint for standalone textual application execution."""
    parser = argparse.ArgumentParser(
        prog="python3 -m tui.app",
        description="WAFBench Full-Screen Interactive Terminal UI (Textual Mode)\n"
                    "Academic 4-View Console adhering strictly to AGENTS.md rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--view",
        dest="initial_view",
        choices=["1", "2", "3", "4"],
        default="1",
        help="Initial view index to display (1=Matrix, 2=Inspector, 3=Canary, 4=Exclusions). Default: 1.",
    )
    parser.add_argument(
        "--ascii",
        dest="ascii_only",
        action="store_true",
        help="Force pure ASCII borders for limited SSH terminals.",
    )
    parser.add_argument(
        "--test-run",
        action="store_true",
        help="Run self-test headless verification and exit cleanly with code 0.",
    )

    args = parser.parse_args()

    view_map = {
        "1": "view1",
        "2": "view2",
        "3": "view3",
        "4": "view4",
    }
    target_view = view_map.get(args.initial_view, "view1")

    if args.test_run:
        # Headless automated verification
        async def _verify() -> None:
            app = WAFBenchTUI(initial_view=target_view, ascii_only=args.ascii_only)
            async with app.run_test() as pilot:
                print("[OK] Textual application composed and mounted successfully.")
                await pilot.press("1")
                assert app.query_one("#view-switcher", ContentSwitcher).current == "view1"
                await pilot.press("2")
                assert app.query_one("#view-switcher", ContentSwitcher).current == "view2"
                await pilot.press("3")
                assert app.query_one("#view-switcher", ContentSwitcher).current == "view3"
                await pilot.press("4")
                assert app.query_one("#view-switcher", ContentSwitcher).current == "view4"
                print("[OK] Keybindings 1, 2, 3, 4 verified cleanly.")
                await pilot.press("r")
                print("[OK] Keybinding 'r' (Refresh) executed cleanly.")
                await pilot.press("q")
                print("[OK] Keybinding 'q' (Quit) executed cleanly.")

        asyncio.run(_verify())
        sys.exit(0)

    # Launch live interactive full-screen app
    app = WAFBenchTUI(initial_view=target_view, ascii_only=args.ascii_only)
    app.run()


if __name__ == "__main__":
    main()
