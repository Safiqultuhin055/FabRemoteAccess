from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Environment, Settings

REMOTE = "db.example.internal"
ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"


def test_env_example_loads_and_documents_every_setting():
    s = Settings(_env_file=ENV_EXAMPLE)
    assert not s.db_configured and s.db_trust_server_cert is False and s.db_encrypt == "yes"
    documented = set(re.findall(r"^(FR_[A-Z0-9_]+)=", ENV_EXAMPLE.read_text(encoding="utf-8"), re.MULTILINE))
    expected = {f"FR_{name.upper()}" for name in Settings.model_fields}
    assert expected <= documented, sorted(expected - documented)


def test_defaults_are_safe(make_settings):
    s = make_settings()
    assert s.env is Environment.DEVELOPMENT
    assert not s.db_configured
    assert s.db_encrypt == "yes" and s.db_trust_server_cert is False
    assert s.openapi_enabled
    assert s.describe_database() == "not configured"
    with pytest.raises(RuntimeError):
        _ = s.db_connection_string


def test_reads_fr_environment_variables(monkeypatch):
    monkeypatch.setenv("FR_ENV", "test")
    monkeypatch.setenv("FR_DB_HOST", REMOTE)
    monkeypatch.setenv("FR_CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example")
    s = Settings(_env_file=None)
    assert s.env is Environment.TEST and s.db_host == REMOTE
    assert s.cors_allowed_origins == ("https://a.example", "https://b.example")


def test_env_file_values_are_loaded_when_enabled(tmp_path, monkeypatch):
    env_file = tmp_path / "custom.env"
    env_file.write_text("FR_DB_HOST=(localdb)\\Example\nFR_DB_PORT=1500\n", encoding="utf-8")
    s = Settings(_env_file=env_file)
    assert s.db_host == "(localdb)\\Example" and s.db_port == 1500


@pytest.mark.parametrize("user", ["sa", "SA", " sa "])
def test_sa_is_rejected(make_settings, user):
    with pytest.raises(ValidationError, match="must not be 'sa'"):
        make_settings(db_host=REMOTE, db_user=user, db_password="x")


def test_password_required_with_user(make_settings):
    with pytest.raises(ValidationError, match="FR_DB_PASSWORD is required"):
        make_settings(db_host=REMOTE, db_user="fr_app")


@pytest.mark.parametrize("overrides", [{"db_trust_server_cert": True}, {"db_encrypt": "optional"}, {"db_encrypt": "no"}])
def test_relaxed_tls_refused_for_remote_server_even_in_development(make_settings, overrides):
    with pytest.raises(ValidationError, match="only allowed for a local server"):
        make_settings(db_host=REMOTE, **overrides)


@pytest.mark.parametrize("host", ["(localdb)\\FabRemoteTest", "localhost", "127.0.0.1"])
def test_relaxed_tls_allowed_for_local_server_in_development(make_settings, host):
    s = make_settings(db_host=host, db_trust_server_cert=True, db_encrypt="optional")
    assert "TrustServerCertificate=yes" in s.db_connection_string


def test_relaxed_tls_refused_outside_development(make_settings):
    with pytest.raises(ValidationError, match="only allowed in development or test"):
        make_settings(env="staging", jwt_signing_key="k" * 32, db_host="localhost", db_trust_server_cert=True)


def test_signing_key_rules(make_settings):
    with pytest.raises(ValidationError, match="at least 32 bytes"):
        make_settings(jwt_signing_key="short")
    with pytest.raises(ValidationError, match="required outside development"):
        make_settings(env="production")
    assert make_settings(env="production", jwt_signing_key="k" * 32).openapi_enabled is False


def test_cors_wildcard_rejected(make_settings):
    with pytest.raises(ValidationError, match="explicit origins"):
        make_settings(cors_allowed_origins="*")


def test_only_fr_schema_supported(make_settings):
    with pytest.raises(ValidationError, match="FR_DB_SCHEMA"):
        make_settings(db_schema="dbo")


def test_invalid_encrypt_and_log_format(make_settings):
    with pytest.raises(ValidationError):
        make_settings(db_encrypt="maybe")
    with pytest.raises(ValidationError):
        make_settings(log_format="xml")


def test_blank_values_mean_unset(make_settings):
    s = make_settings(db_host="  ", db_user="", jwt_signing_key="")
    assert s.db_host is None and s.db_user is None and s.jwt_signing_key is None


def test_remote_connection_string(make_settings):
    s = make_settings(db_host=REMOTE, db_port=1444, db_user="fr_app", db_password="p}w;d",
                      db_server_certificate=r"C:\certs\sql.cer", db_host_name_in_certificate="sql01.example")
    cs = s.db_connection_string
    assert f"SERVER=tcp:{REMOTE},1444" in cs
    assert "Encrypt=yes" in cs and "TrustServerCertificate=no" in cs
    assert "PWD={p}}w;d}" in cs and "Trusted_Connection" not in cs
    assert r"ServerCertificate={C:\certs\sql.cer}" in cs and "HostNameInCertificate=sql01.example" in cs


def test_localdb_connection_string_uses_instance_name(make_settings):
    cs = make_settings(db_host="(localdb)\\FabRemoteTest", db_encrypt="optional").db_connection_string
    assert "SERVER=(localdb)\\FabRemoteTest;" in cs and "tcp:" not in cs
    assert "Trusted_Connection=yes" in cs


def test_secrets_never_appear_in_repr_or_description(make_settings):
    s = make_settings(db_host=REMOTE, db_user="fr_app", db_password="TopSecret-123",
                      jwt_signing_key="J" * 40)
    for text in (repr(s), str(s), s.describe_database(), str(s.model_dump())):
        assert "TopSecret-123" not in text and "J" * 40 not in text
    assert REMOTE not in s.describe_database()
