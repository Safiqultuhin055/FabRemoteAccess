"""run_all.py: reuse a running server, never start a second one, stop only what it started."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("run_all", ROOT / "run_all.py")
run_all = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_all)


class FakeProcess:
    def __init__(self, exited=False):
        self.exited = exited
        self.terminated = False

    def poll(self):
        return 0 if self.exited or self.terminated else None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


class Completed:
    returncode = 0


def test_reuses_running_server_and_does_not_stop_it(monkeypatch):
    started = []
    monkeypatch.setattr(run_all, "server_ready", lambda timeout=1.0: True)
    monkeypatch.setattr(run_all.subprocess, "Popen", lambda *a, **k: started.append(a) or FakeProcess())
    monkeypatch.setattr(run_all.subprocess, "run", lambda *a, **k: Completed())
    monkeypatch.setattr(run_all.webbrowser, "open", lambda url: None)
    assert run_all.main() == 0
    assert started == []          # no second server


def test_starts_server_then_stops_it_when_desktop_closes(monkeypatch):
    server = FakeProcess()
    states = iter([False, True])  # not running at first, then ready
    monkeypatch.setattr(run_all, "server_ready", lambda timeout=1.0: next(states, True))
    monkeypatch.setattr(run_all.subprocess, "Popen", lambda *a, **k: server)
    monkeypatch.setattr(run_all.subprocess, "run", lambda *a, **k: Completed())
    opened = []
    monkeypatch.setattr(run_all.webbrowser, "open", opened.append)
    assert run_all.main() == 0
    assert server.terminated and opened == ["http://127.0.0.1:8765/"]


def test_reports_failure_when_server_exits_early(monkeypatch):
    monkeypatch.setattr(run_all, "server_ready", lambda timeout=1.0: False)
    monkeypatch.setattr(run_all.subprocess, "Popen", lambda *a, **k: FakeProcess(exited=True))
    monkeypatch.setattr(run_all.webbrowser, "open", lambda url: (_ for _ in ()).throw(AssertionError("no browser")))
    assert run_all.main() == 1
