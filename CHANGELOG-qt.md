# FireTunnel Qt Client — Changelog

## v0.12b

### ✨ New features

**Per-app split tunnel rules**
New *Per-app rules* panel in Settings lets you choose which applications route through the VPN and which bypass it directly. Processes are enumerated at runtime via the new `ProcessManager` class with deduplication by path and automatic filtering of system processes (kernel_task, Dock, Finder, etc.). Includes a search bar and group-select for quick rule management. Rules persist across sessions in `AppSettings`.

**QR code export for configs**
Each config in the list now has a QR button that displays the base64-encoded TOML — scan it with the Android client to import instantly.

**Config list: show server instead of path**
The config list now shows the hostname/server from the TOML rather than the raw file path, making it easier to identify connections at a glance.

**Remember last config on startup**
The app pre-selects the last used config when launched.

**Traffic stats per session**
RX / TX byte counters are shown in the main window for the current session.

---

### 🐛 Bug fixes

**UI freeze on connect/reconnect** — fixed
`doConnectAttemptInThread()` used `this` (main-thread object) as the Qt signal receiver context, causing the blocking connect call to be posted to the main event loop via `QueuedConnection`, freezing the entire UI. Fixed by using the worker object (moved to `m_connectThread`) as context so the lambda executes on the background thread.

**Connection slot accumulation → crash** — fixed
Every reconnect attempt added a new `QThread::started → lambda` connection without removing the previous one. After *N* reconnects the slot fired *N* times per thread start, launching *N* parallel `doConnectAttempt()` calls and triggering a data race on `m_client`. Fixed by calling `disconnect(&m_connectThread, &QThread::started, nullptr, nullptr)` before each new `connect()`.

**Teardown race → use-after-free on disconnect** — fixed
`teardownClient()` and `disconnectVpn()` called `m_client.reset()` after `wait(5000)` timed out while the connect thread was still blocked inside a native call (`m_client->connect()`, `set_system_dns`). Fixed by raising the wait timeout to 15 s and calling `terminate()` + `wait()` as a last resort.

**Crash on sleep / network disconnect** — fixed
`teardownClient()` was callable from the main thread while `m_connectThread` was actively running `m_client->connect()`, resetting `m_client` while the thread still held a reference (use-after-free). Fixed by stopping and joining the thread before reset, skipped only when called from within the connect thread itself to avoid deadlock.

**Stuck in WaitingForNetwork forever** — fixed
After sleep/wake or a brief network interruption the core sometimes remained in `WAITING_FOR_NETWORK` indefinitely with no self-recovery path. Added a 30 s single-shot `m_networkWaitTimer` that triggers a clean teardown + `scheduleReconnect()` if the state persists. The timer is cancelled on any active state (CONNECTED, CONNECTING, RECOVERING, DISCONNECTED) and on explicit disconnect.

---

### 🔧 Build / CI

- `bootstrap_conan_deps.py` now self-installs `pyyaml` via `sys.executable` before invoking external sub-scripts (`dns-libs/scripts/export_conan.py`, `native-libs-common/scripts/export_conan.py`) — fixes `ModuleNotFoundError: No module named 'yaml'` on Windows runners where multiple Python versions coexist.
- Removed dead `import yaml` from `bootstrap_conan_deps.py` (leftover from a refactored `conandata.yml` loop).
- Added explicit `pyyaml` pre-install to the Windows job in `run-tests.yml`.

---

## v0.11b

- Minimalist UI redesign — clean card-based layout, adaptive ring indicator
- Theme-adaptive icons (light / dark)
- Traffic stats (RX/TX) in the main window
- ConfigWizard: multi-step guided setup for new configurations

## v0.10b

- Reorganised Settings into tabbed sections
- Embedded SVG icons (no external resource files)
- Bypass and file-descriptor reliability fixes

## v0.9b

- File descriptor monitoring and health-check mechanism
- Fixed domain bypass exclusions accumulating across reconnects
- Fixed deduplicated connection-info log spam (bypass/tunnel)

## v0.8b

- Adapter discovery & deactivation
- SSH / P2P traffic bypass
- Network settings: custom DNS, domain bypass list, adapter conflict scanner

## v0.6b

- Advanced Settings tab
- Auto-update via GitHub Releases API
- Windows Firewall rules added by installer
