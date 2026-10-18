# Fabulous Remote — Desktop client (preview)

PySide6 client following the design mockup. **Preview:** it opens without signing in, registers this computer **without an account** and shows its Remote ID. A signed-in helper enters another computer's Remote ID and presses **Connect**; that computer shows a consent dialog (who is asking, scam warning, Reject by default) and only an explicit **Accept** creates a session. Both sides then see a banner with **Disconnect**. Nothing is simulated, and there is **no screen sharing or remote control yet**: a session confirms consent only.

## Run

The backend must be running (see [backend/README.md](../backend/README.md)), by default at `http://127.0.0.1:8765`.

```powershell
cd "E:\Python Project\FabRemoteAccess"
.\.venv\Scripts\Activate.ps1
pip install -r desktop\requirements.txt
$env:PYTHONPATH = "desktop"
python -m fabremote                          # or: python -m fabremote --api-url https://api.example.com
```

The server address can also be set with `FR_DESKTOP_API_URL`. Only `https://`, or `http://` to this computer, is accepted.

## "This device" card

States: **Not registered**, **Registration pending**, **Verifying identity**, **Online**, **Offline**, **Registration failed**, with progress, retry ("Try again" / "Check again") and accessible names.

| Mode | Data source | What you see |
|---|---|---|
| Default (live) | **Real device API** (Phase 3d) | Register This Device → Registration pending → Verifying identity → Online/Offline, all confirmed by the server. On restart the stored registration is resumed (no second registration) |
| `--preview-device-states success\|failure\|offline\|verify-failure` | **Sample data** (`PreviewDeviceGateway`) | All states, with a red **PREVIEW · sample data** badge and "PREVIEW DATA" in the window title |

```powershell
python -m fabremote --preview-device-states failure    # first attempt fails, Try again succeeds
```

**Device key:** an Ed25519 key pair is created on first registration. The private key is encrypted with Windows **DPAPI** for the current Windows user and stored in `%LOCALAPPDATA%\Fabulous Remote\devices\<server>.json` (`FR_DESKTOP_DATA_DIR` overrides the folder). Only the public key and signatures are sent. A heartbeat signed with the key runs every 15 s; the server shows the device online for 90 s after the last verified heartbeat. If the server reports the device revoked or unknown, the local key is discarded. If a registration response is lost, the next attempt starts over with a new key (the lost Remote ID is never reissued).

The state model refuses impossible states (e.g. Online without a verified identity, or a malformed or early Remote ID), so the card cannot show them even by mistake.

## Windows installer

```powershell
.\.venv\Scripts\python.exe desktop\packaging\build.py
```

Needs PyInstaller (in `requirements-dev.txt`) and [Inno Setup 6](https://jrsoftware.org/isinfo.php). The build also **publishes** the installer to the landing page (`web\site\downloads\` + `latest.json` with size and SHA-256; git-ignored), which enables the page's Download button at http://127.0.0.1:8765/#download. Use `--no-publish` to skip. Output:
`dist\installer\FabulousRemote-Setup-<version>-preview.exe` (the one-folder app is in `dist\desktop\FabulousRemote\`). The script prints the SHA-256.

| Property | Behaviour |
|---|---|
| Install scope | Per user, `%LOCALAPPDATA%\Programs\Fabulous Remote`, no administrator rights |
| Server address | Asked by the wizard; written to `%APPDATA%\Fabulous Remote\config.json`. Must be `https://` (or `http://` to this computer) |
| Unattended | `Setup.exe /VERYSILENT /CURRENTUSER /SERVER=https://your-server` (an invalid address aborts with exit code 1) |
| System changes | Start-menu shortcut (desktop shortcut optional). **No service, no auto-start, no firewall rules** |
| Uninstall | Apps & features, or `unins000.exe`. Removes the app, the shortcuts and the config file |
| Signing | **Not code-signed yet**: SmartScreen shows "Windows protected your PC" → *More info* → *Run anyway*. A signing certificate is needed before distribution |

## Security notes

- **HTTPS is verified against the Windows certificate store** (truststore), so a company or internal CA installed on the PC is trusted. `FR_DESKTOP_CA_BUNDLE` can name a CA file instead. Verification cannot be switched off, and plain `http` is accepted only for this computer.
- Build an installer with the server pre-filled: `python build_installer.py --default-server https://<server>:300 --no-publish` (see [deploy/README.md](../deploy/README.md)).

- Tokens are kept **in memory only** and discarded on sign-out or exit. Saving the refresh token in Windows Credential Manager is planned with device registration.
- Refresh calls are serialised: the server revokes a session if one refresh token is used twice.
- The app opens without signing in. Registering this computer and answering requests need no account; **Connect** (asking to connect to another computer) asks you to sign in first.
- This computer proves itself with a short-lived **device token** (signed challenge, kept in memory only). Requests and sessions are polled every 2 s; reading a session is also the presence signal, so the server ends it when either side disappears.
- Consent dialog: Reject is the default button, closing the dialog rejects, it closes by itself when the request expires, and *Block this person* stops further requests from that account.
- Sign-in errors are generic, and the password field is cleared after a failure.

## Layout

| Path | Purpose |
|---|---|
| `fabremote/app.py` | Entry point: opens the main window signed out; Sign in → signed-in window; Sign out → signed out |
| `fabremote/api_client.py` | HTTP client (httpx): login, refresh rotation, `/auth/me`, logout, health |
| `fabremote/workers.py` | Runs HTTP calls off the UI thread |
| `fabremote/device.py`, `device_controller.py` | This-device state model, gateways (real API / preview) and transitions |
| `fabremote/device_identity.py` | Ed25519 key, DPAPI storage, signed message formats |
| `fabremote/connection.py` | Connection requests and sessions: gateway, incoming (consent) and outgoing controllers |
| `fabremote/ui/consent_dialog.py` | Accept / Reject dialog for incoming requests |
| `fabremote/ui/device_card.py` | The "This device" card |
| `fabremote/ui/` | `theme.py` (colours, icons), `login_dialog.py`, `main_window.py` |
| `tests/` | Headless tests (Qt offscreen, mocked HTTP) |
