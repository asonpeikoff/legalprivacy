"""legalPrivacy v2 CLI.

    legalprivacy run [--profile P] [--once] [--dry-run] [--verbose]
    legalprivacy doctor [--profile P]
    legalprivacy relay gen --bandwidth 5Mbit --nickname mylegalprivacy [--bridge]
    legalprivacy relay doctor
    legalprivacy ui [--no-browser] [--port N]        dashboard (same as double-clicking)
    legalprivacy tor status|start|install|newnym
    legalprivacy relay gen-client [--type snowflake|obfs4] | bridges
"""

from __future__ import annotations

import argparse
import sys
import time

from .config import ConfigError, load_profile
from .relay import RelayConfigError, RelaySpec, generate_torrc, warn_if_exit_requested
from .scheduler import MaxFailuresExceeded, Runner, build_lanes


def _init_random(seed_env: str = "LEGALPRIVACY_SEED"):
    """Deterministic seed for reproducible test runs, random otherwise."""
    import os
    import random
    env = os.environ.get(seed_env) or os.environ.get("CRICKET_SEED")
    return random.Random(int(env)) if env else random.Random()


def cmd_run(args: argparse.Namespace) -> int:
    from .engines import load_wordlist
    profile = load_profile(args.profile)
    rng = _init_random()
    active_wordlist = next((e.wordlist for e in profile.engines.values() if e.enabled and e.wordlist), None)
    wordlist = load_wordlist(active_wordlist)
    tor_mgr = None
    gate = endpoint = None
    tor_cfg = profile.transports.get("tor")
    if tor_cfg and tor_cfg.enabled and not args.dry_run:
        tor_mgr = _bring_up_tor(profile, verbose=args.verbose)
        if tor_mgr is not None:
            gate = lambda: tor_mgr.ready                                     # noqa: E731
            endpoint = lambda: (tor_mgr.socks_addr, tor_mgr.control_addr)     # noqa: E731
    try:
        lanes = build_lanes(profile, wordlist, rng, tor_gate=gate, tor_endpoint=endpoint)
        for lane in lanes:
            if lane.name == "tor" and tor_mgr is not None:
                lane.transport.cookie_path = tor_mgr.cookie_path
        if not lanes:
            print("no active lanes: enable a transport in the profile", file=sys.stderr)
            return 2
        if args.dry_run:
            for lane in lanes:
                engines = ", ".join(f"{e} ({lane.budgets[e].remaining})"
                                    for e in lane.engines)
                print(f"lane {lane.name:8s} transport={type(lane.transport).__name__:18s} "
                      f"engines: {engines}")
            return 0
        if args.reconnect_tor:
            for lane in lanes:
                if hasattr(lane.transport, "reconnect"):
                    ok = lane.transport.reconnect()
                    if args.verbose:
                        print(f"Tor circuit reset requested: {'OK' if ok else 'failed (control port offline)'}")
        # one-shot runs get a fixed clock hour so tests are deterministic
        runner = Runner(
            profile=profile,
            lanes=lanes,
            wordlist=wordlist,
            clock=time.time,
            local_hour_fn=(lambda: 12.0) if args.once else None,
            verbose=args.verbose,
        )
        if args.once:
            runner.run_once(wait=False)
            return 0
        report = runner.run()
        for lane_name, engines in report.items():
            for eng, spent in engines.items():
                print(f"{lane_name}/{eng}: {spent} hits")
        return 0
    finally:
        if tor_mgr is not None:        # never leave the private Tor running after the command ends
            tor_mgr.stop()


def _bring_up_tor(profile, verbose: bool = False):
    """Start (and if needed install) Tor for CLI runs; wait for bootstrap. None on failure."""
    from .events import EventLog
    from .tormanager import TorManager
    cfg = profile.transports["tor"]
    log = EventLog()
    if verbose:
        log.subscribe(lambda e: print(f"  [{e.source}] {e.message}") if e.source == "tor" else None)
    tm = TorManager(log, mode="managed" if cfg.manage else "external", socks=cfg.socks,
                    control=cfg.control, control_password=cfg.control_password,
                    bridges=cfg.bridges, auto_install=cfg.auto_install,
                                  bridge_mode=cfg.bridge_mode, bridge_auto=cfg.bridge_auto)
    tm.start()
    deadline = time.time() + 300
    last = -1
    while time.time() < deadline and tm.state not in ("ready", "error"):
        if tm.bootstrap_pct != last:
            last = tm.bootstrap_pct
            print(f"  Tor: {tm.state} {last}%", flush=True)
        time.sleep(1)
    if tm.state != "ready":
        print(f"  Tor unavailable ({tm.error or 'timed out'}); continuing without the Tor lane.", file=sys.stderr)
        return None
    print(f"  Tor ready on {tm.socks_addr}")
    return tm


def cmd_ui(args: argparse.Namespace) -> int:
    from .webui import run_ui
    return run_ui(args.profile, args.port, False if args.no_browser else None)


def cmd_tor(args: argparse.Namespace) -> int:
    from .events import EventLog
    from .tormanager import TorManager, find_tor_binary
    profile = load_profile(args.profile)
    cfg = profile.transports["tor"]
    log = EventLog()
    log.subscribe(lambda e: print(f"  [{e.level}] {e.message}"))
    tm = TorManager(log, mode="managed" if cfg.manage else "external", socks=cfg.socks,
                    control=cfg.control, control_password=cfg.control_password,
                    bridges=cfg.bridges, auto_install=cfg.auto_install,
                                  bridge_mode=cfg.bridge_mode, bridge_auto=cfg.bridge_auto)
    if args.tor_command == "status":
        print(f"tor program : {find_tor_binary() or 'not installed'}")
        print(f"enabled     : {cfg.enabled}  (managed={cfg.manage}, onion={cfg.onion})")
        return 0
    if args.tor_command == "install":
        tm._install()
        return 0
    if args.tor_command == "start":
        tm.start()
        try:
            while tm.state not in ("ready", "error"):
                time.sleep(1)
            if tm.state == "ready":
                print(f"Tor ready: SOCKS {tm.socks_addr}  control {tm.control_addr}. Ctrl+C to stop.")
                while True:
                    time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            tm.stop()
        return 0 if tm.error is None else 1
    if args.tor_command == "newnym":
        return 0 if TorManager(log, mode="external", socks=cfg.socks, control=cfg.control,
                               control_password=cfg.control_password).new_identity() else 1
    return 2


def cmd_doctor(args: argparse.Namespace) -> int:
    import os
    profile = load_profile(args.profile)
    problems = []
    warnings = []

    total_hits = sum(e.budget_per_day for e in profile.engines.values() if e.enabled)
    print(f"Doctor diagnostics for profile '{profile.name}':")
    print(f"  [+] Schedule: {total_hits} hits/day planned across {len(profile.engines)} engines.")

    # 1. Wordlist check
    active_wordlist = next((e.wordlist for e in profile.engines.values() if e.enabled and e.wordlist), None)
    if active_wordlist and not os.path.exists(active_wordlist):
        problems.append(f"wordlist file not found: {active_wordlist}")
    elif active_wordlist:
        try:
            with open(active_wordlist, encoding="utf-8", errors="ignore") as fh:
                w_count = sum(1 for line in fh if line.strip())
            print(f"  [+] Wordlist: '{active_wordlist}' verified ({w_count:,} words).")
        except OSError:
            problems.append(f"could not read wordlist: {active_wordlist}")

    # 2. Clearnet check
    clearnet_cfg = profile.transports.get("clearnet")
    if clearnet_cfg and clearnet_cfg.enabled:
        proxy_info = clearnet_cfg.proxy or "direct connection"
        print(f"  [+] Clearnet lane: enabled ({proxy_info})")

    # 3. Tor check with live port probing
    tor_cfg = profile.transports.get("tor")
    if tor_cfg and tor_cfg.enabled:
        from .transports import TorTransport
        tor = TorTransport(socks=tor_cfg.socks, control=tor_cfg.control,
                           identities_per_circuit=tor_cfg.identities_per_circuit,
                           control_password=tor_cfg.control_password)
        tor_status = tor.check_status()
        if tor_status["socks_ok"]:
            print(f"  [+] Tor SOCKS daemon ({tor_status['socks_host']}:{tor_status['socks_port']}): CONNECTED")
        else:
            if tor_cfg.manage:
                print("  [i] Tor: not running yet — legalPrivacy starts (and installs, if needed) its own private Tor automatically.")
            else:
                warnings.append(f"Tor SOCKS daemon offline at {tor_status['socks_host']}:{tor_status['socks_port']}")
                print(f"  [-] Tor SOCKS daemon ({tor_status['socks_host']}:{tor_status['socks_port']}): OFFLINE")
                print("      Action: start your Tor, or set transports.tor.manage: true to let legalPrivacy run its own")

        print(f"  [+] Tor modes: onion={'on' if tor_cfg.onion else 'off'}")
        if tor_cfg.control:
            if tor_status["control_ok"]:
                ver = f" (Tor {tor_status['version']})" if tor_status.get("version") else ""
                boot = f" [{tor_status['bootstrap']}]" if tor_status.get("bootstrap") else ""
                print(f"  [+] Tor Control port ({tor_cfg.control}): AUTHENTICATED{ver}{boot}")
            else:
                warnings.append(f"Tor Control port unreachable or unauthenticated at {tor_cfg.control}")
                print(f"  [-] Tor Control port ({tor_cfg.control}): UNAVAILABLE (automatic NEWNYM rotation disabled)")

    if not any(tr.enabled for tr in profile.transports.values()):
        problems.append("no transport enabled in profile")

    for name, eng in profile.engines.items():
        if eng.enabled and eng.budget_per_day == 0:
            problems.append(f"engine '{name}' enabled with zero budget")

    if profile.relay.enabled:
        if profile.relay.mode not in ("middle", "bridge"):
            problems.append("relay mode is not middle/bridge — refusing")
        else:
            print(f"  [+] Relay contribution: enabled ({profile.relay.mode} relay '{profile.relay.nickname}')")

    if warnings:
        for w in warnings:
            print(f"  [warning] {w}", file=sys.stderr)
    if problems:
        for p in problems:
            print(f"  [problem] {p}", file=sys.stderr)
        return 1
    return 0


def cmd_relay(args: argparse.Namespace) -> int:
    if args.relay_command == "gen":
        spec = RelaySpec(mode="bridge" if args.bridge else "middle",
                         nickname=args.nickname or "legalprivacy",
                         contact=args.contact,
                         bandwidth_rate=args.bandwidth)
        torrc = generate_torrc(spec)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(torrc)
        warnings = warn_if_exit_requested(torrc)
        for w in warnings:
            print(w, file=sys.stderr)
        print(f"wrote {args.out}: {spec.mode} relay '{spec.nickname}', "
              f"rate {spec.bandwidth_rate}, exit policy reject-all")
        return 0
    if args.relay_command == "bridges":
        from pathlib import Path
        bridges_path = Path(__file__).resolve().parents[1] / "data" / "bridges" / "bridges.example.txt"
        if bridges_path.exists():
            with open(bridges_path, encoding="utf-8") as fh:
                print(fh.read())
        else:
            from .relay import DEFAULT_SNOWFLAKE_BRIDGES
            print("# Collected Tor Snowflake Bridges:\n")
            for b in DEFAULT_SNOWFLAKE_BRIDGES:
                print(b)
        return 0
    if args.relay_command == "gen-client":
        from .relay import generate_client_torrc
        torrc = generate_client_torrc(bridge_type=args.type)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(torrc)
        print(f"wrote client torrc with {args.type} bridges to {args.out}")
        print(f"To start Tor with this configuration: tor -f {args.out}")
        return 0
    if args.relay_command == "doctor":
        print("relay doctor: verify your relay is reachable from the network via "
              "https://metrics.torproject.org/ after 8h, and that it is NOT listed "
              "as an exit.")
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    from .procname import set_name
    set_name()                          # shows up as "legalprivacy": killall legalprivacy works
    from .paths import ensure_utf8_console
    ensure_utf8_console()
    parser = argparse.ArgumentParser(prog="legalprivacy", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run a noise schedule")
    p_run.add_argument("--profile", help="profile YAML path")
    p_run.add_argument("--once", action="store_true", help="run a single job")
    p_run.add_argument("--dry-run", action="store_true",
                       help="show lanes and budgets without traffic")
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--reconnect-tor", action="store_true",
                       help="signal NEWNYM to rotate Tor circuits before running")
    p_run.set_defaults(func=cmd_run)

    p_ui = sub.add_parser("ui", help="open the dashboard (same as double-clicking legalprivacy-launch)")
    p_ui.add_argument("--profile", help="profile YAML path")
    p_ui.add_argument("--port", type=int)
    p_ui.add_argument("--no-browser", action="store_true")
    p_ui.set_defaults(func=cmd_ui)

    p_tor = sub.add_parser("tor", help="manage the app's private Tor")
    p_tor.add_argument("tor_command", choices=["status", "start", "install", "newnym"])
    p_tor.add_argument("--profile", help="profile YAML path")
    p_tor.set_defaults(func=cmd_tor)

    p_doc = sub.add_parser("doctor", help="validate a profile and probe transport health")
    p_doc.add_argument("--profile", help="profile YAML path")
    p_doc.set_defaults(func=cmd_doctor)

    p_relay = sub.add_parser("relay", help="community relay and bridge management")
    relay_sub = p_relay.add_subparsers(dest="relay_command", required=True)
    p_gen = relay_sub.add_parser("gen", help="generate a non-exit relay torrc")
    p_gen.add_argument("--bridge", action="store_true",
                       help="bridge instead of middle relay")
    p_gen.add_argument("--nickname", help="relay nickname (1-19 alnum)")
    p_gen.add_argument("--contact", help="contact email")
    p_gen.add_argument("--bandwidth", default="5Mbit")
    p_gen.add_argument("--out", default="torrc")
    p_gen.set_defaults(func=cmd_relay)

    p_gen_client = relay_sub.add_parser("gen-client", help="generate client torrc with bridges")
    p_gen_client.add_argument("--type", choices=["snowflake", "obfs4"], default="snowflake",
                              help="bridge technology (snowflake or obfs4)")
    p_gen_client.add_argument("--out", default="torrc.client", help="destination torrc path")
    p_gen_client.set_defaults(func=cmd_relay)

    p_bridges = relay_sub.add_parser("bridges", help="display collected Tor bridges and usage instructions")
    p_bridges.set_defaults(func=cmd_relay)

    relay_sub.add_parser("doctor").set_defaults(func=cmd_relay)

    from . import macspoof
    macspoof.add_parser(sub)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, RelayConfigError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except MaxFailuresExceeded as exc:
        print(f"execution halted: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
