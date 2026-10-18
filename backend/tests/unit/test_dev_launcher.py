"""run_server.py must always target the local LocalDB database, whatever the environment says."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("run_server", ROOT / "run_server.py")
run_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_server)


def test_dev_settings_ignore_environment_and_env_files(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("FR_DB_HOST=192.0.2.10\nFR_DB_USER=someone\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FR_DB_HOST", "192.0.2.10")
    monkeypatch.setenv("FR_DB_USER", "sa")
    monkeypatch.setenv("FR_DB_PASSWORD", "x")
    settings = run_server.dev_settings()
    assert settings.db_host == r"(localdb)\FabRemoteTest" and settings.db_is_local
    assert settings.db_user is None and settings.db_password is None
    assert settings.db_name == "FabRemotesDB_dev" and settings.env.value == "development"
    assert "192.0.2.10" not in settings.db_connection_string
    assert (Path(settings.site_dir) / "index.html").is_file()


def test_port_check_reports_free_port():
    assert run_server.port_in_use("127.0.0.1", 1) is False
