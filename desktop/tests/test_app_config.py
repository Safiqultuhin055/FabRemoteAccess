"""Where the installed client finds its server address."""

from __future__ import annotations

import json

from fabremote.app import DEFAULT_API_URL, configured_api_url


def test_environment_variable_wins(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"api_url": "https://from-file.example"}), encoding="utf-8")
    monkeypatch.setenv("FR_DESKTOP_API_URL", "https://from-env.example")
    assert configured_api_url(config) == "https://from-env.example"


def test_config_file_used_when_no_environment(monkeypatch, tmp_path):
    monkeypatch.delenv("FR_DESKTOP_API_URL", raising=False)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"api_url": "https://remote.example.com"}), encoding="utf-8")
    assert configured_api_url(config) == "https://remote.example.com"


def test_missing_or_broken_config_falls_back_to_local(monkeypatch, tmp_path):
    monkeypatch.delenv("FR_DESKTOP_API_URL", raising=False)
    assert configured_api_url(tmp_path / "absent.json") == DEFAULT_API_URL
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert configured_api_url(broken) == DEFAULT_API_URL
    wrong_type = tmp_path / "list.json"
    wrong_type.write_text("[1, 2]", encoding="utf-8")
    assert configured_api_url(wrong_type) == DEFAULT_API_URL
