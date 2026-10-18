"""Server deployment kit: internal CA, production launcher checks, and a real HTTPS round trip."""

from __future__ import annotations

import importlib.util
import ipaddress
import socket
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.config import Settings

ROOT = Path(__file__).resolve().parents[3]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ca_tool = load("make_internal_ca", "deploy/server/make_internal_ca.py")
production = load("run_production", "deploy/server/run_production.py")


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    out = tmp_path_factory.mktemp("certs")
    assert ca_tool.main(["--ip", "127.0.0.1", "--dns", "localhost", "--out", str(out)]) == 0
    return out


# ------------------------------------------------------------------ internal CA


def test_server_certificate_is_valid_for_the_server_and_signed_by_the_ca(certs):
    ca = x509.load_pem_x509_certificate((certs / "ca.crt").read_bytes())
    server = x509.load_pem_x509_certificate((certs / "server.crt").read_bytes())
    assert server.issuer == ca.subject
    server.verify_directly_issued_by(ca)
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("127.0.0.1") in san.get_values_for_type(x509.IPAddress)
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    assert ExtendedKeyUsageOID.SERVER_AUTH in server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert (certs / "ca.cer").read_bytes()[:1] == b"\x30"            # DER for the Windows certificate store


def test_rerun_reuses_the_ca_and_renews_the_server_certificate(tmp_path):
    assert ca_tool.main(["--ip", "10.0.0.5", "--out", str(tmp_path)]) == 0
    ca_before, server_before = (tmp_path / "ca.crt").read_bytes(), (tmp_path / "server.crt").read_bytes()
    assert ca_tool.main(["--ip", "10.0.0.5", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "ca.crt").read_bytes() == ca_before            # clients keep trusting it
    assert (tmp_path / "server.crt").read_bytes() != server_before


def test_ca_tool_rejects_bad_input(tmp_path):
    assert ca_tool.main(["--ip", "not-an-ip", "--out", str(tmp_path)]) == 2
    assert ca_tool.main(["--out", str(tmp_path)]) == 2                # no name at all


# ------------------------------------------------------------------ launcher checks


def settings(**values) -> Settings:
    base = {"env": "production", "jwt_signing_key": "k" * 40, "db_host": "db.example.internal",
            "db_user": "fr_app", "db_password": "x", "public_base_url": "https://fr.example.internal:300"}
    return Settings(_env_file=None, **{**base, **values})


def test_production_launcher_accepts_complete_configuration(certs):
    assert production.check(settings(), certs / "server.crt", certs / "server.key") == []


@pytest.mark.parametrize("values, missing_tls, expected", [
    ({"env": "development", "jwt_signing_key": None}, False, "staging or production"),
    ({}, True, "TLS certificate not found"),
    ({"db_host": None, "db_user": None, "db_password": None}, False, "FR_DB_HOST"),
])
def test_production_launcher_refuses_unsafe_setups(certs, tmp_path, values, missing_tls, expected):
    cert = tmp_path / "missing.crt" if missing_tls else certs / "server.crt"
    problems = production.check(settings(**values), cert, certs / "server.key")
    assert any(expected in p for p in problems)


def test_production_launcher_rejects_sa_before_starting(monkeypatch, tmp_path, certs):
    env = tmp_path / ".env"
    env.write_text("FR_ENV=production\nFR_JWT_SIGNING_KEY=" + "k" * 40 + "\nFR_DB_HOST=db.example.internal\n"
                   "FR_DB_USER=sa\nFR_DB_PASSWORD=x\n", encoding="utf-8")
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server must not start"))
    assert production.main(["--env-file", str(env), "--cert", str(certs / "server.crt"),
                            "--key", str(certs / "server.key")]) == 2


# ------------------------------------------------------------------ real HTTPS round trip


@pytest.fixture
def https_server(certs):
    import uvicorn

    from app.main import create_app

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(settings(db_host=None, db_user=None, db_password=None), configure_logs=False)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(certs / "server.crt"),
                                           ssl_keyfile=str(certs / "server.key"), log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    yield f"https://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


def test_desktop_client_connects_over_https_when_the_internal_ca_is_trusted(https_server, certs, monkeypatch):
    from fabremote.api_client import ApiClient
    monkeypatch.setenv("FR_DESKTOP_CA_BUNDLE", str(certs / "ca.crt"))
    client = ApiClient(https_server)
    try:
        assert client.health() is True
    finally:
        client.close()


def test_desktop_client_refuses_a_server_it_cannot_verify(https_server, monkeypatch):
    from fabremote.api_client import ApiClient
    monkeypatch.delenv("FR_DESKTOP_CA_BUNDLE", raising=False)
    client = ApiClient(https_server)   # Windows certificate store: the test CA is not trusted there
    try:
        assert client.health() is False
    finally:
        client.close()


def test_plain_http_to_a_lan_address_is_still_refused():
    from fabremote.api_client import validate_base_url
    with pytest.raises(ValueError):
        validate_base_url("http://192.0.2.10:300")
    assert validate_base_url("https://192.0.2.10:300/") == "https://192.0.2.10:300"
