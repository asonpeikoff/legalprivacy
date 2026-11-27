# AGENTS.md: a working guide for AI agents (and new humans)

Read this first. It tells you what legalPrivacy is, where things live, how to run and test it, and the house rules
that keep changes from breaking people's setups. The user-facing story is in `README.md`; the design notes are in
`docs/DESIGN.md`; every release is described in `CHANGELOG.md`.

## What the app does

legalPrivacy makes believable background traffic (web pages in a real browser, plain-HTTP fetches, searches, DNS
lookups, package installs, optional Tor `.onion` visits) so that bulk analysis of someone's traffic says less about
them. It paces itself like a person (daily rhythm, sessions, idle gaps), shows everything it does in a local
dashboard, and keeps nothing after it stops. Extras live around that core: a Tor manager (and an optional public
relay), a Proof tab (is the noise distinguishable from you?), a privacy check, ClamAV front end, MAC spoofing,
a polite site scraper, a load tester, free-proxy tester, remote machines over SSH, and an Android companion app.

## Stack

- **Python 3.10+** package `legalprivacy/` (CI runs 3.12). Dependencies: `requests[socks]`, `PyYAML`, `selenium`,
  `playwright`, `psutil` (see `pyproject.toml`; extras: `dev`, `desktop`, `remote`, `parity`).
- **Two front ends over one controller**, kept in step:
  - Web dashboard: `legalprivacy/web/index.html`, one self-contained file (vanilla JS, no build step). Served by
    `webui.py` (stdlib HTTP server, JSON API under `/api/...`).
  - Native desktop app: Tkinter, `gui.py` plus `gui_*.py` (one file per group of tabs).
- **Android app**: `android/` (Kotlin, Gradle; built only in CI by `.github/workflows/android.yml`).
- `legacy-src/` and `nbproject/` are the 2016 Java prototype. Leave them alone.

## Run it

```bash
pip install -e '.[dev]'
legalprivacy ui                 # web dashboard (same as legalprivacy-launch); --no-browser, --port N
legalprivacy-gui                # the Tk desktop app
legalprivacy run --once --dry-run   # one headless round, nothing sent
legalprivacy doctor             # what is installed and working
./start-legalprivacy.sh         # Linux: start detached; --foreground, --stop
```

Settings live in `config.yaml` under the app folder (`paths.app_dir()`; set `LEGALPRIVACY_HOME` to move it, which
tests do). The web dashboard answers on `http://127.0.0.1:8765` by default.

## Test and lint

```bash
python -m pytest -q             # the whole suite, a few minutes; must pass
python -m pytest -q tests/test_scrape.py   # one area while you work
ruff check .                    # CI runs this too; rules in pyproject.toml
```

- Tests never touch the network on their own: `tests/conftest.py` turns off auto-installs and list downloads and
  stubs the privacy check's public-address lookup. Use local `http.server` fixtures or monkeypatching (see
  `tests/test_scrape.py`) for anything that would fetch.
- Tests use a fresh `Controller(str(tmp_path / "config.yaml"))` with `LEGALPRIVACY_HOME` pointed at `tmp_path`.
- Known sandbox-only failure: `tests/test_relay.py::test_a_relay_left_over_from_an_earlier_run_is_stopped_but_another_window_is_left_alone`
  can fail in some containers (process listing); it passes in GitHub CI.

## Where things live

| Area | Files |
|---|---|
| Entry points | `cli.py` (all subcommands), `launcher.py`, `__main__.py`, `desktop.py` (pywebview window) |
| The hub | `controller.py`: owns the profile, starts and stops the noise, and implements every action both UIs call (`ctl.something(...)`). Most features start here. |
| Settings | `config.py`: dataclasses (`Profile`, `TrafficConfig`, `TransportConfig`, ...), validation, YAML round-trip (`apply_overrides`, `profile_to_dict`). `ConfigError` is the error users see. |
| Scheduling | `scheduler.py` (`Runner`, lanes, hourly mix and pattern), `rate.py` (how much per hour), `pacing.py`, `humanize.py`, `engines.py` (search, crawl, DNS... engines) |
| Transports | `transports.py` (plain HTTP), `browser.py` (Playwright real browser), `realfirefox.py` (your own Firefox via Selenium), `torlane.py` |
| Tor | `tormanager.py` (install, run or attach, monitor), `torcontrol.py` (control-port client), `tordns.py`, `relay.py`/`relayrun.py`, `torbrowser.py`, `anonos.py` (Whonix/Qubes detection) |
| Web API | `webui.py`: routes `/api/...` to controller methods |
| Tk UI | `gui.py` (window, tabs), `gui_tabs.py` (Dashboard, Tor...), `gui_settings.py`, `gui_more.py` (Tools, Help), `gui_security.py`, `gui_remote.py`, `gui_logic.py` (pure helpers, testable without Tk), `gui_theme.py`, `gui_fields.py` |
| Tools tab | `scrape.py`, `loadtest.py`, `proxies.py`, `nettools.py` (speed test, DNS leak check, privacy check), `spray.py` |
| Other features | `macspoof.py` (stdlib only, runs headless in Qubes sys-net), `av.py` (ClamAV), `accounts.py`, `remoteagent.py`/`sshconn.py`, `observe.py`/`netwatch.py`/`fingerprint*.py` (Proof), `selfupdate.py`/`updatecheck.py` |
| Bundled data | `data/` (feeds, wordlists, themes, bridges), `profiles/example.yaml`; rebuilt by scripts in `tools/` |
| Docs | `README.md`, `docs/DESIGN.md`, `docs/MAC.md`, `docs/DOCKER.md` |

## How to make a change

1. **Find the controller method** behind the feature (`grep -n "def scrape_" legalprivacy/controller.py`), then the
   route in `webui.py`, the JS in `web/index.html` (search for the element id) and the Tk code in `gui_*.py`.
2. **Change both UIs.** A setting, button or label added to the web dashboard gets its Tk twin, and the other way
   round. Help text in both (`web/index.html` help cards, `gui_more.py` HelpTab) should agree.
3. **Changing a default?** Saved `config.yaml` files keep old values, so a new default alone reaches only new
   installs. Add a one-time migration: a `migrated_*` flag in `APP_DEFAULTS` (top of `controller.py`) and a block in
   `Controller._load` that moves the old default to the new one once (look at `migrated_anon_off` for the pattern).
   New installs set every `migrated_*` flag to true.
4. **Test it.** Add or update tests in `tests/` (one file per area; test names are sentences that say the
   behaviour). Run the area's tests, then the whole suite, then `ruff check .`.
5. **Write the changelog.** Add a bullet under `## Unreleased` at the top of `CHANGELOG.md`: bold one-line summary,
   then what changed and why, in plain words.

## House style

- **Plain language for people.** UI text, errors and log lines say what happened and what to do, in everyday words,
  no jargon or internal names. Card headings carry no parenthesized asides like "(optional)".
- **Never fail silently.** If an action cannot take effect, say so in its result (a `note` or a `ConfigError`) and in
  the log (`self.log.info/warn/error(source, message)`).
- **Privacy first.** Nothing the user does is stored after the noise stops; no telemetry; network calls only where the
  feature needs them, and documented in the function's docstring.
- **Safety rails stay.** The scraper follows robots.txt and never logs in; noise never visits US DoD address blocks
  (`geoban.py`); Tor-only lanes visit only `.onion`; ordinary noise and DNS never go through Tor.
- Code: 120-column lines, type hints, small helpers over clever one-liners, comments that give the reason.
  Imports of optional packages (`requests`, `playwright`, `paramiko`) happen inside the function that needs them.
- Programs started for the user (file manager, Tor Browser) get `torbrowser.clean_env()`, so the packaged
  (PyInstaller) app's library path does not break them.

## Git and pull requests

- Work on a branch, open a PR against `master`, and let CI (Tests: ruff and pytest) go green.
- The owner merges, or asks for a merge; do not merge on your own.
- Version numbers live in `pyproject.toml` and `legalprivacy/__init__.py`; releases are cut by
  `.github/workflows/release.yml`, so leave them alone unless asked to cut a release.
