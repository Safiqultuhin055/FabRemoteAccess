"""Landing page (web/site): serving, CSP compatibility and honest feature labelling."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.middleware import API_CSP, SITE_CSP
from app.main import create_app

SITE = Path(__file__).resolve().parents[3] / "web" / "site"
INDEX = SITE / "index.html"


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []
        self.inline_script = False
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_script = tag == "script"

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_script = True


@pytest.fixture(scope="module")
def page() -> _Collector:
    collector = _Collector()
    collector.feed(INDEX.read_text(encoding="utf-8"))
    return collector


@pytest.fixture
def client(make_settings):
    app = create_app(make_settings(site_dir=str(SITE)), configure_logs=False)
    return TestClient(app)


def test_site_is_served_at_root_with_site_csp(client):
    response = client.get("/")
    assert response.status_code == 200 and "text/html" in response.headers["content-type"]
    assert "Remote access." in response.text
    assert response.headers["Content-Security-Policy"] == SITE_CSP
    assert client.get("/styles.css").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert client.get("/assets/logo.svg").status_code == 200


def test_api_routes_keep_precedence_and_api_policy(client):
    live = client.get("/health/live")
    assert live.json() == {"status": "ok"} and live.headers["Content-Security-Policy"] == API_CSP
    missing = client.get("/api/v1/nothing-here")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"
    assert client.post("/health/live").json()["error"]["code"] == "method_not_allowed"
    assert client.get("/no-such-page").status_code == 404


def test_site_not_served_unless_configured(make_settings):
    app = create_app(make_settings(), configure_logs=False)
    assert TestClient(app).get("/", follow_redirects=False).status_code == 307  # docs redirect


def test_invalid_site_dir_rejected(make_settings, tmp_path):
    with pytest.raises(ValidationError, match="FR_SITE_DIR"):
        make_settings(site_dir=str(tmp_path))


def test_external_resources_are_pinned_with_sri(page):
    external = [(t, a) for t, a in page.tags
                if (t == "script" and a.get("src", "").startswith("http"))
                or (t == "link" and a.get("href", "").startswith("http"))]
    assert external, "expected Bootstrap from the CDN"
    for _, attrs in external:
        url = attrs.get("src") or attrs.get("href")
        assert url.startswith("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/"), url
        assert attrs.get("integrity", "").startswith("sha384-") and attrs.get("crossorigin") == "anonymous", url


def test_page_is_compatible_with_strict_csp(page):
    html = INDEX.read_text(encoding="utf-8")
    assert not page.inline_script, "inline <script> content is blocked by the CSP"
    assert not re.search(r"\sstyle\s*=", html), "inline style attributes are blocked by the CSP"
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE), "inline event handlers are blocked by the CSP"
    assert "<style" not in html
    allowed_hosts = set(re.findall(r"https://([a-z0-9.-]+)", SITE_CSP))
    used_hosts = {urlparse(a.get("src") or a.get("href")).hostname for t, a in page.tags
                  if (a.get("src") or a.get("href") or "").startswith("http")}
    assert used_hosts <= allowed_hosts


def test_local_references_exist(page):
    for _, attrs in page.tags:
        for key in ("src", "href"):
            ref = attrs.get(key)
            if ref and not ref.startswith(("http", "#", "mailto:", "/")):
                assert (SITE / ref).is_file(), ref
    for anchor in re.findall(r'href="#([\w-]+)"', INDEX.read_text(encoding="utf-8")):
        assert anchor == "top" or f'id="{anchor}"' in INDEX.read_text(encoding="utf-8"), anchor


def test_no_feature_is_claimed_as_available(page):
    html = INDEX.read_text(encoding="utf-8")
    assert "fr-badge-available" not in html and ">Available<" not in html
    assert not re.search(r'href="[^"]+\.(exe|msi|zip)"', html), "no installer exists yet"
    download_button = [a for t, a in page.tags if t == "button" and "disabled" in a]
    assert download_button, "the installer button must stay disabled until a signed build exists"
    assert html.count("fr-badge-planned") >= 3 and html.count("fr-badge-dev") >= 3


# ------------------------------------------------------------------ published installer


def _build_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("desktop_build", SITE.parents[1] / "desktop" / "packaging" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_publish_writes_manifest_and_keeps_one_installer(tmp_path):
    build = _build_module()
    installer = tmp_path / "FabulousRemote-Setup-0.4.0-preview.exe"
    installer.write_bytes(b"MZ fake installer")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    (downloads / "FabulousRemote-Setup-0.3.0-preview.exe").write_bytes(b"old")
    manifest = build.publish_to_site(installer, "0.4.0", downloads)
    import hashlib
    import json
    assert manifest["sha256"] == hashlib.sha256(b"MZ fake installer").hexdigest()
    assert manifest["signed"] is False and manifest["size_bytes"] == len(b"MZ fake installer")
    assert json.loads((downloads / "latest.json").read_text(encoding="utf-8")) == manifest
    assert sorted(p.name for p in downloads.iterdir()) == ["FabulousRemote-Setup-0.4.0-preview.exe", "latest.json"]


def test_published_installer_is_served_with_safe_headers(make_settings, tmp_path):
    import shutil
    site = tmp_path / "site"
    shutil.copytree(SITE, site, ignore=shutil.ignore_patterns("downloads"))
    build = _build_module()
    installer = tmp_path / "FabulousRemote-Setup-0.4.0-preview.exe"
    installer.write_bytes(b"MZ fake installer")
    build.publish_to_site(installer, "0.4.0", site / "downloads")
    client = TestClient(create_app(make_settings(site_dir=str(site)), configure_logs=False))
    manifest = client.get("/downloads/latest.json")
    assert manifest.status_code == 200 and manifest.json()["file"] == installer.name
    download = client.get(f"/downloads/{installer.name}")
    assert download.status_code == 200 and download.content == b"MZ fake installer"
    assert download.headers["X-Content-Type-Options"] == "nosniff"


def test_download_button_is_disabled_until_a_valid_manifest_enables_it():
    html = INDEX.read_text(encoding="utf-8")
    script = (SITE / "app.js").read_text(encoding="utf-8")
    assert 'id="download-button" disabled' in html and 'id="download-details" hidden' in html
    assert "m.signed === false" in script and "SHA256.test(m.sha256)" in script and "INSTALLER_NAME.test" in script
