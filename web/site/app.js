// Fabulous Remote landing page behaviour. No inline scripts (strict CSP).
(function () {
  "use strict";

  // Live service status from the real liveness endpoint; never assumed.
  function showStatus(state, text) {
    var dot = document.getElementById("status-dot");
    var label = document.getElementById("status-text");
    if (!dot || !label) return;
    dot.classList.remove("is-ok", "is-down");
    if (state) dot.classList.add(state);
    label.textContent = text;
  }

  function checkStatus() {
    var controller = typeof AbortController === "function" ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, 5000);
    fetch("/health/live", { cache: "no-store", signal: controller ? controller.signal : undefined })
      .then(function (response) { return response.ok ? response.json() : Promise.reject(response.status); })
      .then(function (body) {
        if (body && body.status === "ok") showStatus("is-ok", "Service online (development build)");
        else showStatus("is-down", "Service status unavailable");
      })
      .catch(function () { showStatus("is-down", "Service status unavailable"); })
      .finally(function () { clearTimeout(timer); });
  }

  // Published installer: enabled only from a valid downloads/latest.json (written by the build).
  var INSTALLER_NAME = /^FabulousRemote-Setup-\d+\.\d+\.\d+-preview\.exe$/;
  var SHA256 = /^[0-9a-f]{64}$/;

  function validManifest(m) {
    return m && typeof m.file === "string" && INSTALLER_NAME.test(m.file) &&
      typeof m.sha256 === "string" && SHA256.test(m.sha256) &&
      typeof m.version === "string" && /^\d+\.\d+\.\d+$/.test(m.version) &&
      typeof m.size_bytes === "number" && m.size_bytes > 0 && m.signed === false;
  }

  function showDownload(m) {
    var button = document.getElementById("download-button");
    var details = document.getElementById("download-details");
    if (!button || !details) return;
    var link = document.createElement("a");
    link.className = button.className;
    link.id = "download-button";
    link.href = "downloads/" + encodeURIComponent(m.file);
    link.setAttribute("download", m.file);
    link.textContent = "Download for Windows (preview)";
    button.replaceWith(link);
    document.getElementById("download-version").textContent = m.version + " (preview)";
    document.getElementById("download-size").textContent = (m.size_bytes / 1048576).toFixed(1) + " MB";
    document.getElementById("download-sha256").textContent = m.sha256;
    var notice = document.getElementById("notice-availability");
    if (notice) notice.textContent = "Fabulous Remote is being built in phases; an unsigned preview of the " +
      "Windows app is available for testing.";
    var text = document.getElementById("download-text");
    if (text) text.textContent = "A preview build is available for testing. It needs a Fabulous Remote server; " +
      "the installer asks for its address.";
    details.hidden = false;
  }

  function checkDownload() {
    fetch("downloads/latest.json", { cache: "no-store" })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (manifest) { if (validManifest(manifest)) showDownload(manifest); })
      .catch(function () { /* no published build: keep "not yet available" */ });
  }

  // Close the mobile menu after choosing a section.
  function closeMenuOnNavigate() {
    var menu = document.getElementById("nav-links");
    if (!menu || !window.bootstrap) return;
    menu.querySelectorAll("a.nav-link").forEach(function (link) {
      link.addEventListener("click", function () {
        if (menu.classList.contains("show")) window.bootstrap.Collapse.getOrCreateInstance(menu).hide();
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var year = document.getElementById("year");
    if (year) year.textContent = String(new Date().getFullYear());
    closeMenuOnNavigate();
    checkStatus();
    checkDownload();
  });
})();
