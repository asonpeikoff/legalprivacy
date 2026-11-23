# Changelog

## Unreleased
- **Your own Firefox is the noise browser** (new default "My own Firefox"): the real program, started on a private copy of your profile with your settings, add-ons and bookmarks. Logins, cookies, saved passwords, form history and the list of pages you visited are never copied; your real profile is only read; the copy is deleted when the browser closes. Needs Selenium (now a dependency) and a Firefox that is not a Snap or Flatpak; otherwise the app falls back to its own browsers and says why. Tested with a stand-in browser, not yet with a live Firefox.
- **README screenshots of every graph and the dashboard**, taken with example data by a new maintainer tool (`tools/make_screenshots.py`): the dashboard, the 6-hour traffic timeline, the live map, the planned pattern, this session against the plan, you against the noise, burst and gap lengths, the match score, off versus on, and the amount, DNS and bridge settings.
- **Fixed:** the "No hits yet" message stayed on screen over a working hits-per-minute graph, and the "peak" label overlapped the tallest bar.
- Active-hours explanations in the charts ("busiest around 4 PM") now use 12-hour times.
- **12-hour times in every chart and menu** (web and desktop): hour labels such as "9 PM" instead of "21:00", clock times with AM/PM, and the active-hours pickers.
- **Run as a service (Linux):** `./start-legalprivacy.sh --service` installs a systemd user service that starts at login and runs with no window (the dashboard is still the web page); `--url` prints the dashboard link and `--uninstall-service` removes it.
- **Searches now lead to the sites visited.** About two thirds of visits to a persona site begin with a topical search (never just the site's name) on a randomly chosen search engine, and the click that follows goes to that site, a few seconds later instead of whenever the dice allow. Clicking a result after a search is also more likely (85%).
- **New default persona "Ason"**: part data scientist, part ordinary web user (Web 2.0 sites, Wikipedia, everyday life, technology, news), part Objectivist (about 14% of visits, drawn from about 100 sites: Objectivist organisations, forums, publications and Substacks, chosen so no single site dominates). Python package installs are about twice as frequent, and .onion visits more than twice as frequent. An existing "Data scientist" setting is switched to Ason once; choose another persona in Settings any time.
- **Fewer repeats:** popular sites in every theme are now favoured gently, so a long list is not dominated by a handful of sites.
- **Defaults:** the relay-avoid list is now strict by default (turn it off in the Tor tab if Tor will not connect), and long sessions are a little more common (about 9% of page visits).
- **Clearer wording:** "Prometheus metrics" is now an Advanced, plain-language option for people who run a monitoring dashboard, and "Mostly when I'm active" is marked not recommended because it shows when you are at the computer. "Ignore it" stays the default.
- **The header logo follows the tab you are on** (main, alternate, main, …) in both the web dashboard (with a fade) and the desktop app (an instant swap). Clicking the web logo still switches it by hand until you change tab. This replaces the 3-minute timer.
- **Clicking the header logo switches** between the two logos at once (and restarts the 3-minute timer).
- **Firefox leads:** when Firefox is installed for the noise browser, most desktop noise identities are Firefox and the rest Chromium; when it is not, none claim to be Firefox (so a user agent never disagrees with the browser running it).
- **DNS defaults:** about two and a half times more DNS lookups, and the mix of normal and secure DNS now stays on your normal DNS 85% of the time.
- **Alternate logo:** the web header alternates between the main logo and a second artwork every 3 minutes, fading one out as the other fades in (instant swap if your system asks for reduced motion). The desktop app keeps the main logo.
- **Logo updated** to the newest artwork (header, desktop app, README).
- **Logo updated** again (header, desktop app, README); the browser-tab icon is unchanged.
- **Larger header logo** (same header height) and a larger, margin-trimmed logo in the README.
- **Logo updated** to the latest version everywhere it appears (dashboard header, browser-tab icon, desktop app, README).
- **Onion sites are named** in Activity and the Live Log (for example "BBC · …" or "Tor Browser Manual · …"), so you can tell what a long .onion address is.
- **Onion list: 37 sites, all checked, and no wandering.** Added 19 public pages from the Tor Project's own published list (blog, support, forum, manuals and more; every address passes the v3 checksum). Removed dark.fail, a link directory that also lists illicit sites. The onion walk now only follows links on the same site or to another site on the list, never to an address nobody vetted.
- **Bigger logo in the same space:** the empty margin around the logo image is trimmed and the logo now fills the header slot, so it is larger and easier to read without making the header taller.
- **Search engine cutting the connection (for example Bing: `ERR_HTTP2_PROTOCOL_ERROR`):** that engine is now rested for 30 to 120 minutes and other engines are used meanwhile, instead of failing repeatedly.
- **Long sessions** (Settings → Extras, on by default): now and then a page, on the regular internet or a .onion site, becomes something the noise keeps going back to for about 15 minutes to 3 hours, or a page left open while "away" for 1 to 4 hours (that route goes quiet), after which it comes back to the same page and carries on. The lane cards show "long session" or "stepped away".
- **Updated logo** (cleaner lettering) in the dashboard header, the browser-tab icon, the desktop app and the README.
- **Fixed: the dashboard said "disconnected" and the Tor tab stayed empty while noise was running.** A drawing error in the lane cards (added with the dashboard redesign) stopped the page from finishing each update, so the status pill showed "disconnected" and the Tor status and circuits were never drawn, even though noise and Tor were working. A drawing problem can no longer be shown as "disconnected", and a new browser test checks the dashboard and Tor tab while running.
- **The browser-tab icon is now the new logo** (the gold "P"); it was still the old green icon. The desktop app uses it as its window icon too.
- Removed the decorative power and Tor icons next to the status pills in the top bar; they looked like buttons but did nothing.
- **Relays to avoid now default to the US plus governmental-looking relays.** The avoid list starts as `{us}`, and a new option (on by default) also avoids relays whose name looks governmental (FBI, NSA, Police, Government, …) or whose contact is a .gov or .mil address, found in the Tor Project's public relay list and refreshed once a day (the Tor tab shows who is being avoided). Names prove nothing, so this is best effort. "Strict" stays off by default so Tor can always connect.
- **Tor Browser button** (Tor tab): downloads the official Tor Browser, installs it only after checking its signature against the Tor Browser Developers key (needs GnuPG), keeps it up to date whenever you open it from here, and launches it separately from the noise (own folder, profile and Tor). Never run as root; on Windows and macOS it sends you to the official download page.
- **The app's own Tor is kept current:** once a day, before it starts, the newest official Tor bundle is looked up and installed if newer. A Tor you installed yourself is never touched.
- **Relays to avoid** (Tor tab): list relay fingerprints or countries (like {ru}) and the app's Tor avoids them for every step it can, optionally strictly. Pasted entries are checked so they can never add another Tor setting.
- **Private bridge:** the relay card has a "Private bridge (only for me)" option for a bridge on your own server that is not handed out to anyone else, and shows a line to copy into Bridges on the computer that should use it (you fill in the server's address). The public relay option is unchanged.
- **DNS lookups and package installs now run alongside everything else**, on their own schedule, instead of taking a share of the same stream. The "Mix of activity" bar is now just searching, following links and .onion sites; DNS lookups and package installs have their own Off/Fewer/Normal/More settings under "Also running in the background". Searches per hour are unchanged.
- **Package noise looks more like real work:** besides single installs, it now sometimes installs a whole requirements file (3 to 14 packages from a web, data or tools stack, with their dependencies). Everything is installed into a temporary folder that is deleted straight after, with pip's cache turned off so nothing is kept.
- **Browser mix by default:** the noise browser now uses every browser it finds, one per identity (Firefox-style identities in Firefox when it is installed for the noise browser, the rest in Chromium), instead of only matching your own. "Browser engine" and "User agent" now default to Mix; choose "Match my own browser only" or a single engine to override. Existing saved settings are kept.
- **Setup questions are always available:** "Setup questions…" under Quick controls and a card at the top of Settings reopen the first-time questions with your current answers filled in.
- **Dashboard redesign:** a status banner ("Protection is on"), a compact Quick controls box (Recommended settings, My settings, Save these as my settings, test visit, shortcuts to every tab), smaller stat tiles, plain-language lane names and tooltips, a short explanation of how Activity and Live Log differ, and 12-hour times everywhere. "Settings updated" now shows the time it applied with the current time under it. The little info buttons now show an "i" and a hover tooltip (they showed a bare question mark).
- **Defaults:** new API and buttons to put all settings back to the recommended values (your list, sign-ins, relay and Tor set-up are kept) and to save and restore your own set. Noise now starts when the app opens by default.
- **User agent mix:** a new option, "Mix: some real, some random", with a percentage (default 70%). That share of the noise identities uses your own browser's user agent and the rest a fresh random one from the library (web Settings and native app). Needs your real user agent (Detect or paste). Setting: `identity.ua_mode: mix`, `identity.ua_own_share`.
- **My List: one-button bookmark import** ("Import bookmarks from Firefox / Chrome"). Also finds Flatpak and `~/.config/mozilla` profiles, and when no browser is found on this computer (for example it lives in another VM or qube) says how to export an HTML file and use "From a file".
- **Tools tab: MAC address card** (read-only: each physical interface now vs factory, with the command to change it).
- **New logo** in the web dashboard header, the desktop app header and window icon, and the README (`docs/logo/legalprivacy-logo.png`).
- **The relay now starts with the app by default**, in practice mode only (loopback, nothing published, nobody can use it). A public relay still needs the checklist once, and the option can be unticked. It stays quiet until Tor is installed.
- **Tools tab:** the data-use estimate moved down. The **DNS check** now also asks the internet which resolver really answered (`whoami.akamai.net`), explains private and Qubes virtual resolver addresses, and notes that on Qubes OS the VPN and encrypted DNS live in other qubes and can't be seen from here (the privacy check says so instead of reporting "no VPN"). New **MAC address** line in the privacy check. **Speed test fixed** (`'dict' object has no attribute 'clearnet'`); endpoints can be overridden with `LEGALPRIVACY_SPEED_DOWN_URL` / `LEGALPRIVACY_SPEED_UP_URL`. Removed the "check whether Tor is in use" link (a normal browser can only ever say no); use Test Tor on the Tor tab.
- **Buttons:** secondary buttons are an accent-coloured outline instead of flat grey, in both the web dashboard and the native app.
- **MAC address spoofing (Linux):** `legalprivacy mac status|randomize|set|restore|rotate`. NetworkManager backend (`random` / `stable`) with an `ip link` fallback, permanent MAC recorded and restorable, default-route interface skipped unless forced, bridges and virtual interfaces never touched, opt-in timed rotation (15 to 1440 minutes) that pauses while a VPN or Tor tunnel is up, no reboot persistence unless `--persist`, `--json` and exit codes 0/1/2/3. Clean-room, standard tools only. Credits the blog *Legalizing Privacy*. Headless and stdlib-only (`legalprivacy-mac`, `python -m legalprivacy.macspoof`); Qubes OS aware: refuses Xen virtual NICs (run it in sys-net), keeps the rotation timer across reboots via `/rw/config/rc.local`.
- **Native app polish:** the header chip now reads "✓ Settings applied 5 min ago" (it was a clock time that never changed); check boxes show real check marks instead of crosses; the Tor tab explains "Run the app's private Tor" versus "Include .onion sites in the noise" and says plainly whether Tor is mixed with the normal noise or Tor only; scroll bars are clearly visible.
- **Tor DNS (optional, off by default).** The managed Tor can answer DNS on a local port (`DNSPort`, loopback only unless you pick one private LAN address and accept the warning). A Test button sends a real lookup through it; the Proof tab gains a "Tor DNS answers" check while it is on. Only A, AAAA and PTR lookups; names are resolved by exit relays, and the Tor lane for noise stays onion-only.
- **Run a relay (optional, off by default).** A Tor-tab screen to run a middle relay or bridge as a separate Tor process with its own data folder: checklist before a public start, read-only torrc, speed limit with a monthly estimate, live log and status, and a "Practice mode (not published)" that listens on loopback only. Never an exit; never starts by itself; stopped on quit and on Panic (hard deletes its data). The relay generator now also writes `ExitRelay 0` and rejects non-ASCII nicknames.
- Web dashboard and native app have the same two cards.
- **Optional antivirus (ClamAV), offline-first** (new Security tab in the web dashboard and the native app). Manages your own ClamAV with an app-owned signature folder; `freshclam` runs only from a confirmed "Update signatures" button; offline import with verification; scans with progress, Stop, results table, Copy path and explicit reversible Quarantine; on Linux the scanner runs with its network removed (`unshare`/`firejail`), on every OS its process tree is watched for any connection (a hit marks the scan NOT OFFLINE and kills it); new "Antivirus scanner stays offline" row on the Proof tab; EICAR self-test built at runtime; Panic (hard) clears quarantine and scan results. No new dependencies.

## v2.14.0
- **Interface polish (web and native), no behaviour change.** Web: design tokens and a designed dark theme with a light/dark toggle, `prefers-contrast` and forced-colors support, WCAG 2.2 AA pass (tab pattern with arrow keys, live status announcements, focus rings, 24px targets, inline validation), round sliders, a labelled mix bar with shaped legend swatches, empty and loading states, and a layout that works down to 360px. Native: round slider handle on a rounded track, flat buttons with hover/pressed/focus states, tidier tab strip that never truncates labels, the "settings in effect" chip in the status bar, flicker-free charts with shaped legends.
- **Security hardening.** Tor bridge lines are validated before they reach Tor's configuration file (a pasted or downloaded line can no longer add other settings); the Tor control client refuses a control password with line breaks and only ever sends a real 32-byte cookie; settings, the dashboard token and the data folder are owner-only; the dashboard compares tokens safely (a non-ASCII token used to crash the handler), times out stalled connections, no longer echoes internal error text to the page (details go to the Live Log), answers bad numbers with a 400, and adds `base-uri`/`form-action` to its content security policy; relay torrc contact and bandwidth values must be single-line; archives from the Tor installer are extracted without links, devices or special permissions.
- **Fixes.** The "this session vs plan" graph now judges whole local hours in half-hour time zones (India, Nepal and others); a HAR recording that spans decades is refused instead of exhausting memory; turning off "refresh sources automatically" now actually stops the timer; the command line stops the private Tor it started; Windows consoles no longer crash on symbols (output is switched to UTF-8); Tor's own output is read as UTF-8; the About box and log now show the right version; closed browser tabs no longer print tracebacks on the console; slow answers no longer stack up dashboard polls.
- **Docs and in-app Help** no longer mention the removed "send ordinary web noise through Tor" switch; the design notes, command lists and the example profile match the current commands.
- **Tests and CI.** CI now runs the whole test suite with pytest (it used to run a hand-kept subset) plus a ruff lint job; new tests for the dashboard's security behaviour, the command line, the Tor installer's checksum and archive handling, and the Tor control client.

## v2.13.0
- **Native desktop app now has everything the web dashboard has** (and a more polished look): the traffic mix and activity mix as stacked bars whose sliders always add up to 100%, rate and randomness, DNS resolver table with per-server verdicts, user agent, extras, persona / interests / household, search-engine weights, realism and query sources, accounts, Tor extras (seeds editor, bridges, Get bridges, circuits, log), My List, ML, Tools, Health and Help tabs, plus the Proof tab's timeline, comparison and address trace. Card layout, drawn icons, primary/secondary/danger buttons, tooltips, empty states, light and dark themes in the web dashboard's colours, high-DPI aware. Only the animated network map is left to the web dashboard (with a button to open it).
- **Data scientist persona now mixes in everyday life** (about 15% of its visits and searches): Gmail, Outlook, YouTube, maps, a bit of shopping and news, and ordinary searches such as "coffee shop near me", on top of the data-science sites.
- More attribution: the README, the dashboard Help tab, the native app (Help menu and About), the package metadata and the release notes now credit and link the blog we are named after, *Legalizing Privacy* by Amy Peikoff.

## v2.12.0
- **Live-apply is now verified:** a "settings in effect" chip in the header, a "Live and verified" message after each change, and a Live Log line listing exactly what changed (private values are not printed).
- **Native desktop app** (`legalprivacy-gui`): a real Tk window, with no browser, web view or HTTP, that talks to the controller directly. Dashboard, Activity, Live Log, Tor, Settings and Proof tabs (checks, the three activity graphs, HAR import), live apply with a "settings in effect" chip, light/dark look, and the web dashboard kept as a backup in the File menu. Uses only Python's built-in Tk (`python3-tk` on Debian/Ubuntu); no new dependencies.
- **Optional desktop window** (`pip install "legalprivacy[desktop]"`, then `legalprivacy-desktop`): the same dashboard in its own window.

## v2.11.0
- **Activity graphs** (Proof tab): the intended pattern for your settings (from the rate planner, for reference), this session's actual requests over the planned band with off-plan hours in red, and your baseline vs the noise by hour of day with burst and quiet-gap lengths. Each has a plain-language verdict and an explanation when there is no data yet.
- **Import a browser recording (HAR file)** as your baseline (Network tab, Save all as HAR). Parsed in memory; only times and site names are read, and only per-minute counts and a deletable list of site names are kept. 50 MB / 500,000 request limits; Chrome and Firefox files.
- **Baseline fallback:** "how you browse" is now the imported HAR, else minutes seen with the noise off, else browser history. The Proof and ML tabs show which is used and how much data it has, and show "not enough data" with how to fix it instead of a score when history is empty or erased. Panic (hard) also deletes the imported data.
- **Optional signed-in accounts** (Settings → Accounts, off by default): the noise browser can browse read-only (load and scroll, never click) while signed in to your own Google and Microsoft accounts. You sign in by hand in a visible window; per-account switch, hourly/daily caps, random escalating pause after a robot check or 429 (with Resume now), never over Tor, separate cookies, deleted by Panic (medium/hard).
- Releases are built for **Linux only** for now. Windows and macOS executables are still under development and are deliberately not being built right now; their build setup is kept (commented out) in the release workflow, and the source launchers still work.
- Removed the "also route ordinary web noise through Tor" option and the Tor exit-country preference. Ordinary web noise never goes through Tor; the Tor lane visits only .onion sites. Old settings files that still contain those keys keep working (the keys are ignored).

## v2.10.2

- **Fix: tabs flickering through other sites.** Some sites, mostly through their ads, send the whole tab through a
  chain of other sites a moment after loading; on phones, a very short swipe could also count as a tap on an ad.
  The noise browser now blocks that: once a page has loaded, its tab can move within the same site, or to the
  result the noise clicked, but a page can't send it anywhere else. The tab simply stays where it was. Swipes are
  always long enough not to be taps.
- **Browser address trace** (Proof tab): every address the noise browser's tabs showed recently, newest first, with
  what made it change: the noise opening a page or clicking a result, the page redirecting itself, or a jump that
  was blocked. The Live Log also warns if a tab ever goes through several different sites within seconds.

## v2.10.1

- **Fix: the noise browser popped up windows.** It was meant to run hidden by default, but it opened an "off-screen"
  window instead, which Linux desktops using Wayland (such as Fedora) put on screen. It now runs hidden by default,
  and older settings go back to hidden too. "Off-screen" is still an option on Windows, macOS and X11; elsewhere it
  runs hidden.
- **One window, tabs:** when you choose to watch it, the noise browser keeps one window and opens pages in tabs.
  Pop-ups and "open in new window" links stay in the same tab.
- **Always the user agent it's given:** every tab, phone or desktop, hidden or visible, uses the identity's own
  user agent and matching client hints, never the browser's. If that can't be set, nothing is visited.
- **English-language sites only:** sites on country domains such as .de, .fr or .jp, language sections such as
  de.example.com or example.com/fr/, and pages that say they're in another language are skipped. A page that turns
  out not to be in English gets a quick look, and then the site is left alone for about a week.

## v2.10.0

- **Data scientist is the default persona**, followed 90% of the time (the rest is everyday browsing); "Nobody in
  particular (neutral)" turns it off. Its searches are mostly real people's: about 8,000 data-science searches from
  MS MARCO (Bing) and GooAQ (Google), advanced only: basic statistics is left out. Its sites are a list of ~115 data-science sites, and more popular ones come up
  more often. Sections of sites (such as reddit.com/r/datascience) are visited as listed.
- **Package installs** (Settings → Extras): real `pip install`, `pip download`, `pip index versions` and
  `pip uninstall` of popular packages, plus `npm view` / `npm install` if npm is installed, so the noise also talks to
  PyPI and npm like someone who codes. Automatic by default: on for the Data scientist and Developer personas.
  It all happens in legalPrivacy's own separate environment, never yours: only ready-built packages, nothing installed
  is ever run, installs are removed again, downloads are deleted, and the environment is rebuilt daily. Never over Tor.

## v2.9.0

- **Personas** (Settings → Extras): pick who the noise mostly looks like: Data scientist, Developer, Sports fan,
  Student, Home cook and gardener, or Traveller. It's followed mostly, not perfectly (60% by default); the rest stays
  varied. New Data science theme with its own sites and searches.
- **Clear logs between restarts** (Settings → General, on by default): the Live Log and Activity start empty each
  time noise starts; untick to keep them across Stop → Start. Both are memory-only and always end when the app quits.
- **Fix:** after Stop → Start, new requests didn't appear in Activity until the count passed the previous run's.
- **Login walls:** pages that require an account (Facebook, Instagram, LinkedIn, X and the like) get a short look,
  then the noise moves on and rests that site for a few hours, like a logged-out visitor. Public pages are browsed
  as usual. It never counts as a failure, and the noise never logs in.
- **New name: legalPrivacy** (formerly noisyCricket), a homage to the blog *Legalizing Privacy*. Commands are now
  `legalprivacy` and `legalprivacy-launch`, start scripts `Start-legalPrivacy.bat` and `start-legalprivacy.sh` /
  `.command`, downloads `legalprivacy-launch-*`, and the Docker service `legalprivacy`.
- **Nothing to redo after updating:** an existing settings folder (`~/.noisycricket`, `%APPDATA%\noisyCricket`) keeps
  being used, the old commands `cricket` and `cricket-launch` still work, and so do `CRICKET_*` environment variables
  (the new `LEGALPRIVACY_*` names take priority).

## v2.8.1

- **Network map explains itself** when it has nothing to draw (psutil missing, watching off, nothing seen yet,
  or only local/private connections such as through a VPN or proxy), and shows any drawing error instead of
  staying blank.
- **Cookies:** the noise browser keeps its own cookies for about an hour by default (was a week), then starts
  fresh, with each set living 60–140% of the chosen time. Choices: don't keep, 1 hour, 6 hours, 1 day, 1 week,
  30 days. Earlier day-based settings carry over.
- **Proof tab map and timeline fixed for installs made before v2.8.0.** The double-click start scripts only
  installed what noisyCricket needs on the very first run, so the new `psutil` requirement was never added and the
  Proof tab stayed empty. They now update the environment whenever the requirements change.
- **`pip install` from GitHub now includes the map.** The map's script file wasn't packaged, so the map showed
  "Map unavailable".
- **Health tab** says whether connection watching and the map are available, and what to do if not.

## v2.8.0

- **Proof tab:** a live EtherApe-style map of every machine this computer talks to (your apps, noisyCricket, Tor),
  6 hours of traffic per minute with the noise-on periods shaded, an off-vs-on table, and a score for how much the
  noise's rhythm looks like your own. Local only; your own connections are never named or saved.
- **Tor bridges:** built-in obfs4, Snowflake and meek bridges from the official Tor bundle, your own saved bridges,
  an automatic fallback when Tor can't connect directly, "get bridges that work here" from the Tor Project's
  bridge service, and shortcuts to request private bridges. Snowflake now works with the current Tor bundle.
- **Patient Tor:** failed onion pages are sometimes reloaded a minute or two later, sometimes skipped; a new identity
  after a varying run of failures; circuits change by themselves every 10–40 minutes. **Test Tor** button and
  plain-English Tor errors.
- **DNS:** your three OpenNIC servers (ns2.de, ns3.de, ns4.de) as primaries with Quad9 as a fallback, in an editable
  table with speed checks and detection of networks that secretly answer DNS themselves.
- **Search engines** that show an "are you a robot?" check rest for a few hours; the browser runs as an off-screen
  real window by default where there is a display.
- **Browsing fixes:** results-page junk links ignored, correct scroll depth on sites that scroll an inner panel,
  back to the results to open another one.
- Tor tab: the onion site list is shown and editable; routing ordinary noise through Tor moved under Advanced.

## v2.7.0

- ML tab: how easily your real browsing can be told apart from the noise (ROC AUC, giveaways, advice).
- Starts within seconds; human time on page and results-page behaviour; quiet handling of offline onion sites.
- Browser engine choice (match your browser, Chromium or Firefox); Docker image; household masking;
  My List imports; popular sites re-ranked by Chrome's real browsing.

## v2.3 – v2.6

- Double-click dashboard with a 3-question setup, optional managed Tor with onion sites, real-browser mode with
  scrolling, reading and clicking, real search queries and real popular sites shipped as a snapshot, hourly
  randomized amount with a slider.

## v2.2.0 and earlier

- Command-line noise generator with separate clearnet and Tor lanes and community relay generation.
