"""The DNS helper: an exit that does only DNS. Its torrc must let out nothing but port 53 of the two named resolvers."""
import pytest

from legalprivacy.config import ConfigError, RelayConfig
from legalprivacy.relay import DNS_HELPER_POLICY, RelayConfigError, RelaySpec, generate_torrc


def _policy_lines(torrc):
    return [ln for ln in torrc.splitlines() if ln.startswith(("ExitPolicy ", "ExitRelay", "IPv6Exit"))]


def test_the_dns_helper_exits_only_dns_to_two_resolvers():
    t = generate_torrc(RelaySpec(mode="dns", practice=True))
    assert "ExitRelay 1" in t and "IPv6Exit 0" in t
    accepts = [ln for ln in t.splitlines() if ln.startswith("ExitPolicy accept")]
    assert accepts == ["ExitPolicy accept 9.9.9.9:53", "ExitPolicy accept 149.112.112.112:53"]
    assert "ExitPolicy reject *:*" in t and t.index("ExitPolicy reject *:*") > t.index("ExitPolicy accept 149.112.112.112:53")
    assert t.rstrip().endswith("ExitPolicy reject6 *:*")                 # nothing can follow the closing reject
    assert DNS_HELPER_POLICY[-1] == "ExitPolicy reject *:*"


def test_the_dns_helper_hardens_the_resolver_and_a_practice_run_publishes_nothing():
    t = generate_torrc(RelaySpec(mode="dns", practice=True))
    for opt in ("ServerDNSRandomizeCase 1", "ServerDNSDetectHijacking 1", "ServerDNSSearchDomains 0"):
        assert opt in t
    assert "ORPort 127.0.0.1:" in t and "PublishServerDescriptor 0" in t and "DirPort 0" in t


def test_the_other_modes_still_exit_nothing_and_a_general_exit_is_still_refused():
    for mode in ("middle", "bridge"):
        t = generate_torrc(RelaySpec(mode=mode, practice=True))
        assert "ExitRelay 0" in t and "ExitPolicy accept" not in t
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(mode="exit"))
    with pytest.raises(ConfigError):
        RelayConfig(mode="exit").validate()
    RelayConfig(mode="dns").validate()                                    # the helper is a valid mode


def test_a_public_dns_helper_still_asks_to_be_reachable_first():
    t = generate_torrc(RelaySpec(mode="dns", practice=False))
    assert "AssumeReachable 0" in t and "ORPort 9001" in t
