"""Profile loading and validation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .rate import RateConfig

DEFAULT_TOR_SOCKS = "127.0.0.1:9050"
DEFAULT_TOR_CONTROL = "127.0.0.1:9051"
DEFAULT_WORDLIST = "data/wordlists/words.txt"
DEFAULT_SEEDS = [
    "https://en.wikipedia.org/wiki/Special:Random",
    "https://en.wikipedia.org/wiki/Randomness",
]


class ConfigError(ValueError):
    """Raised for invalid or unsafe profile configuration."""


# One Tor bridge line: "[transport] address:port [fingerprint] [key=value ...]". It is written into Tor's
# configuration file, so it must stay on one line and start like a bridge (never inject another setting).
_BRIDGE_LINE = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*\s+)?(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]):\d{1,5}"
                          r"(?:\s+[^\x00-\x1f\x7f]*)?$")


# Relays banned for good, by identity fingerprint (Tor never builds a circuit through them). Added at the owner's request:
#   5C62A7A4BFD24D61034499857C4B5E437CD2361F  the relay named "CIA" (a Guard in Luxembourg, contact at a hosting company;
#   probably a joke name, but it is not worth the doubt).
# This is a short, hand-kept list on purpose: guessing from names is no basis for banning (see CHANGELOG), and a list from
# someone else is only worth using if it is known to list bad relays, not to nudge people toward the good ones.
BANNED_RELAYS = {"5C62A7A4BFD24D61034499857C4B5E437CD2361F": 'relay named "CIA"'}


def valid_bridge_line(line: str) -> bool:
    return isinstance(line, str) and len(line) <= 1000 and bool(_BRIDGE_LINE.match(line.strip()))


@dataclass
class EngineConfig:
    enabled: bool = True
    budget_per_day: int = 50
    queries_per_identity: int = 6
    wordlist: str = DEFAULT_WORDLIST
    seeds: list[str] = field(default_factory=lambda: list(DEFAULT_SEEDS))
    max_depth: int = 4
    same_site_only: bool = True

    def validate(self, name: str) -> None:
        if self.budget_per_day < 0 or self.queries_per_identity < 1:
            raise ConfigError(f"engine '{name}': budget/queries must be positive")
        if name == "crawl" and self.enabled and not self.seeds:
            raise ConfigError("engine 'crawl' enabled but seeds list is empty")


@dataclass
class TransportConfig:
    """One transport lane. Tor-only fields are ignored by the clearnet lane.

    Tor is OPTIONAL and off by default. When enabled it visits .onion sites
    (darknet noise). Ordinary web noise never goes through Tor.
    """
    enabled: bool = True
    proxy: str | None = None          # clearnet: http:// or socks5:// URL
    browser: str = "auto"             # clearnet: auto | on | off — drive a real browser like a person
    browser_window: str = "hidden"    # clearnet: hidden (default) | offscreen (a real window placed off-screen,
                                      # only where the system allows it) | visible (watch it work)
    browser_visible: bool = False     # derived from browser_window (kept for older settings files)
    browser_offscreen: bool = False   # derived from browser_window
    firefox_path: str = ""            # clearnet: where your own Firefox is, if the app cannot find it by itself ("" = find it)
    browser_engine: str = "mine"      # clearnet: mine (default: your own Firefox, on a copy of your profile; else mix) | mix | auto | chromium | firefox
    cookie_hours: float = 24.0        # clearnet: keep browser cookies this long (a day: consent choices and 'returning visitor' state, like a real user), then start fresh (0 = never keep)
    cookie_vary: bool = True          # clearnet: each jar lives 60-140% of cookie_hours, so wipes aren't on a fixed beat
    # --- tor lane only ---
    socks: str = DEFAULT_TOR_SOCKS
    control: str | None = None
    identities_per_circuit: int = 8
    control_password: str | None = None
    manage: bool = True               # True: app runs its own private Tor; False: use existing Tor
    auto_install: bool = True         # download official Tor bundle if none is installed
    onion: bool = True                # run the onion engine on the Tor lane
    onion_browser: bool = False       # visit onion sites with the real Tor Browser (scrolling, reading, like a person); opens a window, so off until you switch it on;
                                      # the plain requests lane is the fallback when it can't be started
    onion_seeds: list[str] = field(default_factory=list)   # extra seeds; empty = built-ins
    onion_follow_offsite: bool = True
    bridges: list[str] = field(default_factory=list)       # bridge lines for censored networks
    bridge_mode: str = "off"          # off | obfs4 | snowflake | meek (built into the Tor bundle) | custom (yours)
    bridge_auto: bool = True          # if Tor can't connect directly, try the built-in bridges by itself
    dns_port: int = 0                 # Tor DNS (optional): 0 = off, else the preferred local UDP port for Tor's DNSPort
    dns_lan: bool = False             # share Tor DNS on one private network address (off; loopback only by default)
    dns_lan_addr: str = ""            # which of this computer's private addresses, when dns_lan is on
    exclude_nodes: list[str] = field(default_factory=lambda: ["{us}"])   # relays (fingerprints) or countries Tor avoids
    share_browser: bool = True        # Tor Browser (opened from this app) uses this app's Tor, so your own browsing and the noise share one Tor
    exclude_strict: bool = True       # never use them, even if that means Tor can't connect (turn off if Tor won't connect)

    def validate(self, name: str) -> None:
        if self.browser not in ("auto", "on", "off"):
            raise ConfigError(f"transport '{name}': browser must be auto, on or off")
        if self.browser_window not in ("hidden", "offscreen", "visible"):
            raise ConfigError(f"transport '{name}': browser_window must be hidden, offscreen or visible")
        if self.firefox_path and not os.path.isfile(os.path.expanduser(self.firefox_path)):
            raise ConfigError(f"transport '{name}': the Firefox path you gave does not exist: {self.firefox_path}")
        if self.browser_engine not in ("mine", "mix", "auto", "chromium", "firefox"):
            raise ConfigError(f"transport '{name}': browser_engine must be mine, mix, auto, chromium or firefox")
        if self.bridge_mode not in ("off", "obfs4", "snowflake", "meek", "custom"):
            raise ConfigError("tor bridge_mode must be off, obfs4, snowflake, meek or custom")
        for n in self.exclude_nodes:
            if not valid_exclude_entry(n):
                raise ConfigError(f"'{n}' isn't a relay fingerprint (40 letters and digits) or a country like {{ru}}")
        for b in self.bridges:
            if not valid_bridge_line(b):
                raise ConfigError("a Tor bridge line isn't in the usual form (for example "
                                  "'obfs4 192.0.2.1:443 FINGERPRINT cert=… iat-mode=0'); paste one bridge per line")
        if self.identities_per_circuit < 1:
            raise ConfigError(f"transport '{name}': identities_per_circuit >= 1")
        if name == "tor":
            from .tordns import TorDnsError, validate_dns
            try:
                validate_dns(self.dns_port, self.dns_lan, self.dns_lan_addr)
            except TorDnsError as exc:
                raise ConfigError(str(exc)) from exc


def valid_exclude_entry(entry: str) -> bool:
    """A relay fingerprint (optionally with a leading $) or a two-letter country in braces. Nothing else:
    the entry goes into the torrc, so it must never be able to carry another setting."""
    return bool(re.fullmatch(r"\$?[0-9A-Fa-f]{40}|\{[A-Za-z]{2}\}", entry or ""))


@dataclass
class RelayConfig:
    enabled: bool = True
    mode: str = "middle"              # middle | bridge — NEVER an exit
    nickname: str = "legalprivacy"
    contact: str | None = None
    bandwidth_rate: str = "5Mbit"
    or_port: int = 9001
    dir_port: int = 9030
    practice: bool = False            # practice mode: loopback only, nothing published (an option; not the default)
    autostart: bool = True            # start the relay with the app (on by default: a public non-exit relay)
    acknowledged: bool = True         # the checklist's facts were accepted (on by default; the Tor tab explains them)
    private: bool = False             # bridge only: a private bridge for your own use, not handed out to anyone else

    def validate(self) -> None:
        from .relay import RelayConfigError
        if self.mode not in ("middle", "bridge"):
            raise ConfigError(
                "contribute.relay.mode must be 'middle' or 'bridge'; "
                "legalPrivacy never runs an exit node"
            )
        try:             # one set of rules (including the line-break checks) for every way a torrc is made
            self.spec().validate()
        except RelayConfigError as exc:
            raise ConfigError(str(exc)) from exc

    def spec(self):
        from .relay import RelaySpec
        return RelaySpec(mode=self.mode, nickname=self.nickname, contact=None,      # never published: a contact address is public
                         bandwidth_rate=self.bandwidth_rate, or_port=self.or_port,
                         dir_port=self.dir_port, practice=self.practice, private=self.private)


RECOMMENDED_RESOLVERS = [
    {"ip": "80.152.203.134", "name": "OpenNIC ns2.de", "role": "primary", "enabled": True,
     "note": "OpenNIC, Germany (admin keke); anonymized logs"},
    {"ip": "193.31.24.55", "name": "OpenNIC ns3.de", "role": "primary", "enabled": True,
     "note": "OpenNIC, Germany (admin Koby, sponsored by n4x2.com)"},
    {"ip": "80.153.146.105", "name": "OpenNIC ns4.de", "role": "primary", "enabled": True,
     "note": "OpenNIC, Germany"},
    {"ip": "9.9.9.9", "name": "Quad9", "role": "fallback", "enabled": True,
     "note": "Used only if the primaries are down or slow. Blocks malware domains, DNSSEC"},
]


@dataclass
class DnsConfig:
    """Which resolver the DNS noise uses. See legalprivacy/dnsplan.py."""
    mode: str = "secure"          # secure (default: only the resolver table) | mix (blocks on your normal DNS + the table) | system
    encrypted: bool = True        # DNS over TLS (port 853, certificate checked, never plain text) to the secure resolvers
    resolvers: list[dict] = field(default_factory=lambda: [dict(r) for r in RECOMMENDED_RESOLVERS])
    slow_ms: int = 250            # a primary slower than this counts as "not working fast"
    opennic: bool = False         # extra: the whole OpenNIC no-log directory as primaries
    quad9: bool = False           # extra: Quad9 (9.9.9.9 / 149.112.112.112) as primaries
    custom: list[str] = field(default_factory=list)   # extra resolver IPs, your choice
    system_share: float = 0.85    # mix mode: share of time on your normal DNS (the rest on the secure resolvers)
    block_minutes: list[int] = field(default_factory=lambda: [10, 60])   # mix mode: switch every 10-60 min

    def validate(self) -> None:
        import ipaddress
        if self.mode not in ("system", "secure", "mix"):
            raise ConfigError("dns.mode must be system, secure or mix")
        for ip in self.custom:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError as exc:
                raise ConfigError(f"dns.custom: '{ip}' is not an IP address") from exc
        if not 0 <= self.system_share <= 1:
            raise ConfigError("dns.system_share must be between 0 and 1")
        clean = []
        for r in self.resolvers:
            ip = str(r.get("ip", "")).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ConfigError(f"DNS resolver '{ip}' is not an IP address") from exc
            role = r.get("role", "primary")
            if role not in ("primary", "fallback"):
                raise ConfigError("DNS resolver role must be primary or fallback")
            clean.append({"ip": ip, "name": str(r.get("name") or ip)[:40], "role": role,
                          "enabled": bool(r.get("enabled", True)), "note": str(r.get("note", ""))[:160]})
        self.resolvers = clean


@dataclass
class IdentityConfig:
    """Which user agent the plain-HTTP noise sends. See legalprivacy/useragents.py."""
    ua_mode: str = "mix"          # mix (default: your own browser's for most, others for the rest) | pin | rotate
    rotate_every: str = "hour"    # hour | day   (rotate mode: how often the choice changes)
    ua_pin: str = "own"           # pin mode: "own" or a library id. "own" with no UA yet = rotate until known
    own_ua: str = ""              # your browser's user agent (stored only on this computer)
    ua_own_share: float = 0.85    # mix mode: share of identities that use your own browser's user agent (0 to 1);
                                  # the rest get a random one from the library

    def validate(self) -> None:
        if self.ua_mode not in ("rotate", "pin", "mix"):
            raise ConfigError("identity.ua_mode must be rotate, pin or mix")
        if not 0 <= float(self.ua_own_share) <= 1:
            raise ConfigError("identity.ua_own_share must be between 0 and 1")
        if self.rotate_every not in ("hour", "day"):
            raise ConfigError("identity.rotate_every must be hour or day")
        if len(self.own_ua) > 600:
            raise ConfigError("identity.own_ua is too long")


@dataclass
class ExtrasConfig:
    """Optional extras: active hours, interests, household, activity-aware pacing and more."""
    active_hours: bool = False    # only make noise between active_from and active_to (local time)
    active_from: int = 8
    active_to: int = 23
    search_engines: dict = field(default_factory=dict)   # engine -> relative weight 0..10; {} = defaults
    typos: bool = False           # occasionally misspell a word in a search, as people do
    low_data: bool = False        # real browser skips images, video and fonts
    daily_data_mb: float = 0.0    # stop for the day after this much data; 0 = no cap
    polite: bool = False          # at least a minute between visits to the same site
    browser_dns: bool = True      # look names up like a browser: A, plus AAAA and HTTPS records
    dns_bursts: bool = True       # a lookup is often followed by the burst of lookups a page load makes (fonts, scripts, other sites)
    interests: bool = False       # interest personas: a few steady themes at a time
    interest_list: list = field(default_factory=list)   # themes allowed ([] = all)
    interest_active: int = 3      # how many themes at once
    interest_rotate_days: int = 10
    interest_share: float = 0.3   # share of visits and searches that follow the themes
    spray: bool = False           # Spray and Pray: an extra layer of fast DNS lookups for hundreds to thousands of different domains
    spray_level: str = "medium"   # low | medium | high (about 25 / 120 / 400 queries a second on average)
    keep_alive: bool = True       # wake the noise if it stops or pauses itself, or gets stuck (a pause you asked for is left alone)
    file_transfers: bool = True   # now and then download a real file (photo, video, zip...) and throw it away, or upload random bytes
    duck_chat: bool = True        # made-up chats on duck.ai, often (accepts duck.ai's terms for you; switch it off here if you do not want that)
    duck_images: bool = True      # in some of those chats, attach a made-up picture through the page's own file button and ask about it
    geoban: bool = True           # never visit, route through or keep anything at an address in Virginia or a government range
    multi_tab: bool = True        # now and then open a link in a second tab, read the first, then glance at it
    long_sessions: bool = True    # now and then stay on one page a long time, or leave it open for hours and come back
    interest_salt: str = ""       # random, set on first use: keeps your themes yours
    activity: str = "off"         # your own activity: off | backoff | follow
    busy_kbps: int = 400          # backoff: pause while your own traffic is above this
    metrics: bool = False         # Prometheus metrics at /metrics (needs the dashboard token)
    site_list: str = "both"       # both = Tranco re-ranked by Chrome's real browsing (CrUX), default | tranco
    persona: str = "Default mix"  # who the noise mostly looks like ("" = nobody in particular)
    persona_share: float = 0.8    # how closely the persona is followed (share of visits and searches); the rest is random
    packages: str = "auto"        # real pip/npm installs (removed again): auto (techy personas) | on | off
    household: bool = False       # noise from a virtual household of several people
    household_size: int = 3       # 2..5 people, member 1 = you

    def validate(self) -> None:
        from .engines import ENGINE_NAMES
        if self.spray_level not in ("low", "medium", "high"):
            raise ConfigError("extras.spray_level must be low, medium or high")
        for k in ("active_from", "active_to"):
            if not 0 <= int(getattr(self, k)) <= 23:
                raise ConfigError(f"extras.{k} must be an hour from 0 to 23")
        if self.daily_data_mb < 0:
            raise ConfigError("extras.daily_data_mb must be 0 or more")
        for name, w in self.search_engines.items():
            if name not in ENGINE_NAMES:
                raise ConfigError(f"extras.search_engines: unknown engine '{name}'")
            if float(w) < 0:
                raise ConfigError("extras.search_engines weights must be 0 or more")
        if self.search_engines and not any(float(w) > 0 for w in self.search_engines.values()):
            raise ConfigError("Leave at least one search engine on.")
        from .interests import CATEGORIES
        for c in self.interest_list:
            if c not in CATEGORIES:
                raise ConfigError(f"extras.interest_list: unknown theme '{c}'")
        if not 1 <= int(self.interest_active) <= len(CATEGORIES):
            raise ConfigError("extras.interest_active is out of range")
        if not 1 <= int(self.interest_rotate_days) <= 365:
            raise ConfigError("extras.interest_rotate_days must be 1 to 365")
        if not 0 <= float(self.interest_share) <= 1:
            raise ConfigError("extras.interest_share must be between 0 and 1")
        if self.activity not in ("off", "backoff", "follow"):
            raise ConfigError("extras.activity must be off, backoff or follow")
        from .interests import PERSONAS
        if self.persona and self.persona not in PERSONAS:
            raise ConfigError(f"extras.persona: unknown persona '{self.persona}'")
        if not 0 <= float(self.persona_share) <= 1:
            raise ConfigError("extras.persona_share must be between 0 and 1")
        if self.packages not in ("auto", "on", "off"):
            raise ConfigError("extras.packages must be auto, on or off")
        if not 2 <= int(self.household_size) <= 5:
            raise ConfigError("extras.household_size must be 2 to 5")
        if self.site_list not in ("both", "tranco"):
            raise ConfigError("extras.site_list must be both or tranco")
        if int(self.busy_kbps) < 10:
            raise ConfigError("extras.busy_kbps must be at least 10")


@dataclass
class TrafficConfig:
    """What kinds of noise run, in what proportions, and how the mix changes over time.

    Clearnet noise never goes through Tor in these mixes; .onion noise always does.
    """
    pattern: str = "drift"        # drift (default) | blend | alternate
    browser: float = 100.0        # clearnet pages in a real browser (relative weight)
    plain: float = 0.0            # clearnet pages over plain HTTP (no JavaScript, no scrolling)
    onion: float = 100.0          # Tor .onion sites (only when Tor is on): as much as the browser pages
    mobile_share: float = 0.10    # share of noise identities that are phones (emulated on this computer, so kept low)
    device: str = "iPhone 13"     # phone to emulate, or "mix"

    def validate(self) -> None:
        from .useragents import MOBILE_DEVICES
        if self.pattern not in ("drift", "blend", "alternate"):
            raise ConfigError("traffic.pattern must be drift, blend or alternate")
        for k in ("browser", "plain", "onion"):
            if float(getattr(self, k)) < 0:
                raise ConfigError(f"traffic.{k} must be 0 or more")
        if not 0 <= self.mobile_share <= 1:
            raise ConfigError("traffic.mobile_share must be between 0 and 1")
        if self.device != "mix" and self.device not in MOBILE_DEVICES:
            raise ConfigError("traffic.device: unknown phone '" + self.device + "'")


@dataclass
class MyListConfig:
    """Your own sites (My List). Page visits and DNS lookups come from here first."""
    enabled: bool = False
    sites: list[str] = field(default_factory=list)   # site names, most-visited first
    weights: dict = field(default_factory=dict)        # site -> how often, 1 (rarely) .. 10 (very often)
    random_share: float = 0.3     # share of visits/lookups from the other sources instead
    watch_started: float = 0.0    # "recording" window start (unix time); 0 = not recording
    watch_hours: float = 24.0     # recording window length

    def validate(self) -> None:
        if not 0 <= self.random_share <= 1:
            raise ConfigError("mylist.random_share must be between 0 and 1")
        if not 1 <= self.watch_hours <= 72:
            raise ConfigError("mylist.watch_hours must be between 1 and 72")
        for s in self.sites:
            if not s or " " in s or "/" in s or "." not in s or len(s) > 253:
                raise ConfigError(f"mylist: '{s}' is not a site name like example.com")


@dataclass
class AccountConfig:
    """One optional signed-in account (Google or Microsoft). OFF by default; see accounts.py."""
    enabled: bool = False
    per_hour: int = 3               # at most this many signed-in visits an hour (1-10)
    per_day: int = 12               # and this many a day
    on_challenge: str = "pause"     # after a robot check / "too many requests": pause (random while) | continue

    def validate(self, name: str) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigError(f"accounts.{name}.enabled must be true or false")
        for k, lo, hi in (("per_hour", 1, 10), ("per_day", 1, 100)):
            v = getattr(self, k)
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise ConfigError(f"accounts.{name}.{k} must be a whole number from {lo} to {hi}")
        if self.on_challenge not in ("pause", "continue"):
            raise ConfigError(f"accounts.{name}.on_challenge must be pause or continue")


ACCOUNT_PROVIDERS = ("google", "microsoft")


@dataclass
class QuerySources:
    """Where search queries come from (mixed; none dominates). See queries.py."""
    live: bool = True        # Google Trends, Wikipedia most-read, BBC headlines (refreshed daily)
    dataset: bool = True     # real past searches: MS MARCO (Bing) + GooAQ (Google autocomplete)
    builtin: bool = True     # small hand-written topic list (kept a minority on purpose)
    words: bool = True       # occasional dictionary word ("define …", "… meaning")


@dataclass
class Profile:
    name: str
    realtime_scale: float = 1.0
    engines: dict[str, EngineConfig] = field(default_factory=lambda: {
        "search": EngineConfig(budget_per_day=120),
        "crawl": EngineConfig(budget_per_day=40),
        "dns": EngineConfig(budget_per_day=480),     # 3x searches + link-following ("More")
        "onion": EngineConfig(budget_per_day=40, max_depth=3),
        "packages": EngineConfig(budget_per_day=28),
        "files": EngineConfig(budget_per_day=10),
    })
    transports: dict[str, TransportConfig] = field(default_factory=lambda: {
        "clearnet": TransportConfig(),
        "tor": TransportConfig(enabled=False, socks=DEFAULT_TOR_SOCKS, control=DEFAULT_TOR_CONTROL),
    })
    relay: RelayConfig = field(default_factory=RelayConfig)
    daily_max_failures: int = 30        # no longer used: failures never pause or stop the noise (kept so old settings files still load)
    queries: QuerySources = field(default_factory=lambda: QuerySources())
    rate: RateConfig = field(default_factory=lambda: RateConfig())
    dns: DnsConfig = field(default_factory=lambda: DnsConfig())
    identity: IdentityConfig = field(default_factory=lambda: IdentityConfig())
    mylist: MyListConfig = field(default_factory=lambda: MyListConfig())
    traffic: TrafficConfig = field(default_factory=lambda: TrafficConfig())
    extras: ExtrasConfig = field(default_factory=lambda: ExtrasConfig())
    accounts: dict[str, AccountConfig] = field(
        default_factory=lambda: {n: AccountConfig() for n in ACCOUNT_PROVIDERS})

    def active_engines(self, transport: str) -> list[str]:
        """Engines a lane runs. Onion is Tor-only; clearnet engines never run over Tor."""
        on = [n for n, e in self.engines.items() if e.enabled and (n != "packages" or self.packages_on())
              and (n != "files" or (self.extras.file_transfers and not self.extras.low_data))]
        if transport == "tor":
            on = [n for n in on if n != "packages"]           # package installs never go over Tor
        if transport == "clearnet":
            return [n for n in on if n != "onion"]
        if transport == "tor":
            tor = self.transports.get("tor")
            if not (tor and tor.onion and "onion" in on):
                return []
            return ["onion"] + (["files"] if "files" in on else [])      # Tor also carries some of the file downloads
        return []

    def packages_on(self) -> bool:
        """Package-manager noise: auto = on for the Data scientist and Developer personas."""
        from .packages import TECHY_PERSONAS
        mode = self.extras.packages
        return mode == "on" or (mode == "auto" and self.extras.persona in TECHY_PERSONAS)

    def clearnet_lane_count(self) -> int:
        """How many lanes share the clearnet engines' daily budgets."""
        return 1


def _engine(raw: dict[str, Any] | None) -> EngineConfig:
    return EngineConfig(**{k: v for k, v in (raw or {}).items() if k in
                           EngineConfig.__dataclass_fields__})


def _transport(raw: dict[str, Any] | None) -> TransportConfig:
    return TransportConfig(**{k: v for k, v in (raw or {}).items() if k in
                              TransportConfig.__dataclass_fields__})


def profile_to_dict(profile: Profile) -> dict[str, Any]:
    from dataclasses import asdict
    return {"profile": {
        "name": profile.name,
        "realtime_scale": profile.realtime_scale,
        "engines": {n: asdict(e) for n, e in profile.engines.items()},
        "transports": {n: asdict(t) for n, t in profile.transports.items()},
        "daily_max_failures": profile.daily_max_failures,
        "contribute": {"relay": asdict(profile.relay)},
        "queries": asdict(profile.queries),
        "rate": asdict(profile.rate),
        "dns": asdict(profile.dns),
        "identity": asdict(profile.identity),
        "mylist": asdict(profile.mylist),
        "traffic": asdict(profile.traffic),
        "extras": asdict(profile.extras),
        "accounts": {n: asdict(a) for n, a in profile.accounts.items()},
    }}


def save_profile(profile: Profile, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{__import__('threading').get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        yaml.safe_dump(profile_to_dict(profile), fh, sort_keys=False)
    os.replace(tmp, path)


def apply_overrides(profile: Profile, raw: dict[str, Any]) -> Profile:
    """Merge a (possibly partial) profile dict over an existing Profile, validating."""
    p = raw.get("profile", raw)
    profile.name = p.get("name", profile.name)
    if "realtime_scale" in p:
        profile.realtime_scale = float(p["realtime_scale"])
    for name, raw_eng in (p.get("engines") or {}).items():
        if name in profile.engines:
            merged = profile.engines[name].__dict__ | (raw_eng or {})
            profile.engines[name] = EngineConfig(
                **{k: v for k, v in merged.items() if k in EngineConfig.__dataclass_fields__})
    for name, raw_tr in (p.get("transports") or {}).items():
        if name in profile.transports:
            raw_tr = dict(raw_tr or {})
            if "cookie_days" in raw_tr and "cookie_hours" not in raw_tr:      # settings from v2.8.0
                raw_tr["cookie_hours"] = float(raw_tr["cookie_days"] or 0) * 24
            if "browser_window" not in raw_tr and ("browser_visible" in raw_tr or "browser_offscreen" in raw_tr):
                # Older settings: the off-screen window was switched on without being asked for, so it
                # goes back to hidden; a visible window someone chose stays visible.
                raw_tr["browser_window"] = "visible" if raw_tr.get("browser_visible") else "hidden"
            merged = profile.transports[name].__dict__ | raw_tr
            if name == "tor":
                try:
                    merged["dns_port"] = int(merged.get("dns_port") or 0)
                except (TypeError, ValueError):
                    raise ConfigError("Tor DNS port must be a whole number") from None
                merged["dns_lan"] = merged.get("dns_lan") is True
                merged["dns_lan_addr"] = str(merged.get("dns_lan_addr") or "").strip()
            t = profile.transports[name] = TransportConfig(
                **{k: v for k, v in merged.items() if k in TransportConfig.__dataclass_fields__})
            t.browser_visible, t.browser_offscreen = t.browser_window == "visible", t.browser_window == "offscreen"
    contribute = p.get("contribute") or {}
    if "relay" in contribute:
        merged = profile.relay.__dict__ | contribute["relay"]
        if merged.get("mode") == "dns":                         # the older "DNS helper" (an exit) is gone: it becomes a middle relay
            merged["mode"] = "middle"
        try:
            for k in ("or_port", "dir_port"):
                merged[k] = int(merged[k])
        except (TypeError, ValueError):
            raise ConfigError("relay ports must be whole numbers") from None
        for k in ("enabled", "practice", "autostart", "acknowledged"):
            merged[k] = merged[k] is True
        merged["nickname"], merged["bandwidth_rate"] = str(merged["nickname"]), str(merged["bandwidth_rate"])
        merged["contact"] = str(merged["contact"]) if merged.get("contact") else None
        profile.relay = RelayConfig(**{k: v for k, v in merged.items() if k in RelayConfig.__dataclass_fields__})
    if p.get("queries"):
        merged = profile.queries.__dict__ | p["queries"]
        profile.queries = QuerySources(**{k: bool(v) for k, v in merged.items()
                                          if k in QuerySources.__dataclass_fields__})
    if p.get("rate"):
        merged = profile.rate.__dict__ | p["rate"]
        profile.rate = RateConfig(**{k: v for k, v in merged.items() if k in RateConfig.__dataclass_fields__})
        profile.rate.level = float(profile.rate.level)
        profile.rate.randomness = float(profile.rate.randomness)
        try:
            profile.rate.validate()
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    if p.get("dns"):
        merged = profile.dns.__dict__ | p["dns"]
        if isinstance(merged.get("custom"), str):
            merged["custom"] = [x.strip() for x in merged["custom"].replace(",", "\n").splitlines() if x.strip()]
        if merged.get("reset_resolvers"):
            merged["resolvers"] = [dict(r) for r in RECOMMENDED_RESOLVERS]
        profile.dns = DnsConfig(**{k: v for k, v in merged.items() if k in DnsConfig.__dataclass_fields__})
        profile.dns.system_share = float(profile.dns.system_share)
        profile.dns.validate()
    if p.get("identity"):
        merged = profile.identity.__dict__ | p["identity"]
        vals = {k: v for k, v in merged.items() if k in IdentityConfig.__dataclass_fields__}
        share = vals.pop("ua_own_share", None)
        profile.identity = IdentityConfig(**{k: str(v) for k, v in vals.items()})
        if share is not None:
            try:
                profile.identity.ua_own_share = float(share)
            except (TypeError, ValueError):
                raise ConfigError("identity.ua_own_share must be a number between 0 and 1") from None
        profile.identity.validate()
    if p.get("extras"):
        m = profile.extras.__dict__ | p["extras"]
        profile.extras = ExtrasConfig(
            active_hours=bool(m["active_hours"]), active_from=int(m["active_from"]), active_to=int(m["active_to"]),
            search_engines={str(k): float(v) for k, v in (m.get("search_engines") or {}).items()},
            typos=bool(m["typos"]), low_data=bool(m["low_data"]), daily_data_mb=float(m["daily_data_mb"]),
            polite=bool(m["polite"]), browser_dns=bool(m["browser_dns"]), dns_bursts=bool(m["dns_bursts"]),
            interests=bool(m["interests"]), interest_list=[str(x) for x in (m.get("interest_list") or [])],
            interest_active=int(m["interest_active"]), interest_rotate_days=int(m["interest_rotate_days"]),
            interest_share=float(m["interest_share"]), interest_salt=str(m.get("interest_salt") or ""),
            activity=str(m["activity"]), busy_kbps=int(m["busy_kbps"]), metrics=bool(m["metrics"]),
            site_list="tranco" if m.get("site_list") == "tranco" else "both",
            household=bool(m.get("household")), household_size=int(m.get("household_size") or 3),
            persona=_persona_name(m.get("persona")), persona_share=float(m.get("persona_share", 0.8)),
            packages=str(m.get("packages") or "auto"))
        profile.extras.spray_level = str(m.get("spray_level") or "medium")
        for _k, _d in (("long_sessions", True), ("multi_tab", True), ("duck_chat", True), ("duck_images", True), ("file_transfers", True), ("keep_alive", True), ("geoban", True), ("spray", False)):    # fields the call above does not take
            setattr(profile.extras, _k, bool(m.get(_k, _d)))
        if (profile.extras.interests or profile.extras.household) and not profile.extras.interest_salt:
            import secrets as _s
            profile.extras.interest_salt = _s.token_hex(8)
        profile.extras.validate()
    if p.get("traffic"):
        merged = profile.traffic.__dict__ | p["traffic"]
        profile.traffic = TrafficConfig(
            pattern=str(merged["pattern"]), browser=float(merged["browser"]), plain=float(merged["plain"]),
            onion=float(merged["onion"]), mobile_share=float(merged["mobile_share"]), device=str(merged["device"]))
        profile.traffic.validate()
    if p.get("mylist"):
        merged = profile.mylist.__dict__ | p["mylist"]
        sites = merged.get("sites") or []
        if isinstance(sites, str):
            sites = sites.replace(",", "\n").splitlines()
        clean = []
        for x in sites:
            x = str(x).strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            x = x.removeprefix("www.")
            if x and x not in clean:
                clean.append(x)
        merged["sites"] = clean
        weights = {str(k).lower().removeprefix("www."): float(v)
                   for k, v in (merged.get("weights") or {}).items()}
        profile.mylist = MyListConfig(
            enabled=bool(merged.get("enabled")), sites=clean,
            weights={k: min(10.0, max(1.0, v)) for k, v in weights.items() if k in clean},
            random_share=float(merged.get("random_share", 0.3)),
            watch_started=float(merged.get("watch_started") or 0),
            watch_hours=float(merged.get("watch_hours", 24)))
        profile.mylist.validate()
    if p.get("accounts") is not None:
        raw_acc = p["accounts"]
        if not isinstance(raw_acc, dict):
            raise ConfigError("accounts must be a section with google and microsoft")
        for name, raw_a in raw_acc.items():
            if name not in ACCOUNT_PROVIDERS:
                raise ConfigError(f"accounts: unknown account type '{name}'")
            if raw_a is not None and not isinstance(raw_a, dict):
                raise ConfigError(f"accounts.{name} must be a section")
            merged = profile.accounts.get(name, AccountConfig()).__dict__ | (raw_a or {})
            acc = AccountConfig(**{k: v for k, v in merged.items() if k in AccountConfig.__dataclass_fields__})
            acc.validate(name)
            profile.accounts[name] = acc
    if "daily_max_failures" in p:
        profile.daily_max_failures = int(p["daily_max_failures"])
    for name, eng in profile.engines.items():
        eng.validate(name)
    for name, tr in profile.transports.items():
        tr.validate(name)
    profile.relay.validate()
    if profile.realtime_scale <= 0:
        raise ConfigError("realtime_scale must be > 0")
    return profile


def _persona_name(x) -> str:
    from .interests import LEGACY_PERSONA_NAMES
    x = str(x or "")
    return LEGACY_PERSONA_NAMES.get(x, x)


def load_profile(path: str | None) -> Profile:
    """Load a YAML profile, merged over defaults."""
    profile = Profile(name="default")
    if path is None:
        return profile
    if not os.path.exists(path):
        raise ConfigError(f"profile not found: {path}")
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return apply_overrides(profile, raw)
