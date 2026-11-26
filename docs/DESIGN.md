# legalPrivacy v2 — Design

Conversation-driven web-noise generator: one scheduler, identity-realistic
behavior, and fully separate logic for Tor and clearnet traffic. Built fresh;
the 2016 Java prototype lives on in `legacy-src/`.

## What it does

legalPrivacy v2 generates realistic, privacy-preserving web noise so that
mass bulk analysis of any one person's browsing is less useful. It mixes
engine families (search, crawl, DNS, optional package installs and optional
`.onion` visits) over two transports (clearnet and an optional private Tor),
with per-identity consistent fingerprints and human-cadence pacing. Ordinary
web noise and DNS never go through Tor; the Tor lane visits only `.onion`
sites.

## Concept — what a "job" is

A **job** is one round of noise-by-an-identity:

```
identity = (fingerprint, clearnet proxy or Tor circuit, timing persona)
job      = pick engine → pick target(s) → hit with pacing & retries → settle
```

A schedule is a YAML profile that sets per-engine budgets, the day/night
activity curve, transports, and contribution policy. The scheduler drains
budgets over the day, cross-fading engine targets so hit distribution has
no periodic signature.

## Interface

```
legalprivacy ui [--no-browser] [--port N]          # the local dashboard (same as legalprivacy-launch)
legalprivacy run [--profile PROFILE] [--once] [--dry-run] [--verbose]
legalprivacy doctor [--profile PROFILE]
legalprivacy tor status|start|install|newnym
legalprivacy relay gen --bandwidth 5Mbit --nickname mylegalprivacy [--bridge]
legalprivacy relay gen-client [--type snowflake|obfs4] | bridges | doctor
```

The dashboard (`legalprivacy-launch`), the native Tk window (`legalprivacy-gui`) and the optional web-view
window (`legalprivacy-desktop`) all drive the same `Controller`; settings save and apply live.

Profile YAML reference:

```yaml
# profiles/example.yaml
profile:
  name: default
  realtime_scale: 1.0        # speed up >1 for testing, slow down <1
  engines:
    search:
      enabled: true
      budget_per_day: 120
      wordlist: data/wordlists/words.txt
      queries_per_identity: 6
    crawl:
      enabled: true
      budget_per_day: 40
      seeds:
        - https://en.wikipedia.org/wiki/Randomness
      max_depth: 4
      same_site_only: true
    dns:
      enabled: true
      budget_per_day: 200
  transports:
    clearnet:
      enabled: true
      proxy: null                 # or "http://user:pass@proxy:8080", socks5://...
    tor:                          # optional; the Tor lane carries only .onion visits
      enabled: true
      socks: 127.0.0.1:9050
      control: 127.0.0.1:9051     # optional, enables new-circuit control
      identities_per_circuit: 8
      control_password: null      # prompts via LEGALPRIVACY_TOR_CONTROL_PW if needed
  contribute:
    relay:
      enabled: false              # community middle/bridge relay, NEVER an exit
      mode: middle                # middle | bridge
      nickname: mylegalprivacy
      contact: you@example.com
      bandwidth_rate: 5Mbit
      or_port: 9001
      dir_port: 9030
```

## Features

- **Engine budgets** with day/night curve: activity drawn from a lognormal
  cadence modulated by an S-curve diurnal profile in local time, so hit rates
  look like a person's browsing, not a cron job.
- **Per-identity fingerprints**: consistent (UA, Accept-Language, viewport
  hints, query taste) sets pinned per identity; n identities rotate through
  circuits/lifetime across the run.
- **Transport split**: engines emit neutral `Target` objects; transports own
  connection, IP diversity, and failure semantics. Tor lane forces absolute
  isolation between identities; the clearnet transport can use a proxy (and
  keeps a health-checked proxy pool when given one).
- **Pacing**: lognormal inter-hit delays with fast/slow persona multipliers,
  burst suppression, exponential backoff on 403/429/timeouts, soft budget
  floors so the schedule always finishes.
- **Crafted DNS packets** on clearnet (raw UDP, stdlib only) to your normal
  resolver and/or a resolver table, with integrity checks. There is no DNS noise
  over Tor: arbitrary UDP queries cannot traverse Tor circuits, so the Tor lane
  only visits `.onion` sites (which need no DNS).

## Tor vs clearnet — separate logic on purpose

- Tor lane: only `.onion` sites, through one local SOCKS daemon; identities
  get *fresh circuits* (SOCKS5 user/pass isolation or `NEWNYM` via control
  port), no cookie/DNS bleed-through, no HTTP keep-alive across identities.
  Host names are resolved remotely by the circuit, so the local resolver never
  sees a query. Ordinary web noise is never routed through Tor.
- Clearnet lane: direct or through a proxy; identities bound to a proxy +
  UA + language for a lifetime; connect timeouts, retry dimming, and
  proxy-health tracking so a dead proxy dims instead of erroring a lane. A
  real browser (Chrome, Edge, Brave or Chromium) is used when installed, with
  plain HTTP as the other clearnet transport.

## Community contribution — relay, NEVER an exit

`legalprivacy relay gen` emits a **middle-relay or bridge** torrc: `ORPort` +
`DirPort` + `ExitPolicy reject *:*`. The generator refuses any exit-policy
request. Contributing bandwidth back keeps Tor fast for everyone and is the
community-minded counterpart to consuming it.

> Accuracy note: Tor has no "DNS node" role — arbitrary DNS queries cannot be
> relayed. The community-minded equivalent of "a DNS node" is exactly this
> non-exit (middle/bridge) relay: it carries the network's traffic — including
> every end-to-end DNS lookup that exits do perform on behalf of clients.

## Stealth / traffic strategies

- Identity == consistent fingerprint: UA pool mirrors live frequency-weighted
  traffic (multiple Chrome majors circulating, Chrome reduced UA format,
  Android frozen at "Android 10; K", ESR Firefox tails), Accept-Language
  pinned, low-entropy client hints only on Chromium personas (a Sec-CH-UA on
  a Firefox/Safari UA is an instant tell), fetch-metadata navigation headers,
  no DNT (dead in browsers — sending it marks you), Sec-GPC opt-in at
  realistic low rates, query taste per identity (topics drawn from a persona
  word set) so the query distribution mixes, not matches, a sampled
  population.
- Cadence: lognormal pacing from real browsing distributions; fast/slow
  persona multipliers; burst suppression (min gap per identity).
- Failure discipline: 403/429/timeout → exponential backoff with jitter,
  proxy dimming, no failure limit (failures never stop the run; a keep-alive watchdog wakes a stalled one).
- Red-team honesty: this mixes ranks, not miracles. Fingerprinting at the
  router or CDN level is out of scope; do not aim this at sites you love.
