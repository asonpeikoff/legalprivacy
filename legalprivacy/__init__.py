"""legalPrivacy v2 — conversation-driven web-noise generator.

Privacy-preserving web noise: three engine families over two transports,
per-identity consistent fingerprints, human-cadence pacing, and an optional
community relay contribution (middle or bridge; never an exit).
"""

import os as _os

# Programs this app starts (browsers, Tor Browser) try to reach the desktop's accessibility bus and print "failed to create dbus
# proxy for org.a11y.bus ... Permission denied" when they cannot (a service, a sandbox). Tell them not to try.
_os.environ.setdefault("NO_AT_BRIDGE", "1")

__version__ = "2.24.0"
