#!/usr/bin/env python3
"""legalPrivacy test runner — runs the full test suite without external dependencies."""

import inspect
import sys

# Windows consoles default to cp1252, which can't print the check marks below
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure repo root is on python path
sys.path.insert(0, ".")

import tests.test_identity
import tests.test_packages
import tests.test_pacing
import tests.test_relay
import tests.test_scheduler
import tests.test_tor_onion
import tests.test_controller
import tests.test_humanize
import tests.test_browser
import tests.test_sources
import tests.test_rate_dns
import tests.test_mylist
import tests.test_mix_mobile
import tests.test_extras
import tests.test_selftest
import tests.test_cookies
import tests.test_observe
import tests.test_macspoof

MODULES = [
    tests.test_identity,
    tests.test_packages,
    tests.test_pacing,
    tests.test_relay,
    tests.test_scheduler,
    tests.test_tor_onion,
    tests.test_controller,
    tests.test_humanize,
    tests.test_browser,
    tests.test_sources,
    tests.test_rate_dns,
    tests.test_mylist,
    tests.test_mix_mobile,
    tests.test_extras,
    tests.test_selftest,
    tests.test_cookies,
    tests.test_observe,
    tests.test_macspoof,
]


def run_all() -> int:
    passed = 0
    failed = 0
    errors = []

    for mod in MODULES:
        test_fns = [
            (name, fn)
            for name, fn in inspect.getmembers(mod, inspect.isfunction)
            if name.startswith("test_")
        ]
        print(f"\n[{mod.__name__}] ({len(test_fns)} tests)")
        for name, fn in test_fns:
            try:
                fn()
                passed += 1
                print(f"  ✓ {name}")
            except Exception as exc:
                failed += 1
                errors.append((f"{mod.__name__}.{name}", exc))
                print(f"  ✗ {name}: {exc}")

    print("\n" + "=" * 50)
    print(f"Summary: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, exc in errors:
            print(f"  - {name}: {exc}")
        return 1
    print("All tests passed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(run_all())
