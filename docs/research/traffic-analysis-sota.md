# Traffic analysis and anti-analysis: state of the art and product gaps

Prepared 2026-11-24 for the legalPrivacy team. Defensive scope only: protecting ordinary people from mass surveillance, ISP-level profiling and data brokers.

**Evidence level.** Sources were found by search this session. For most papers I read the abstract/snippet, not the full text. Numbers below are the authors' own reported numbers (abstract level), in their lab conditions, and are cited per row. Anything I could not confirm is in "Unverified". Repo statements come from reading `/home/user/noisyCricket/legalprivacy/*.py` (selftest.py, rate.py, transports.py, dnsplan.py, scheduler.py, identity.py, browser.py).

---

## 1. Executive summary

1. **Realism beats volume.** The strongest recent evidence for cover traffic (Wi-Fi MAC-layer study, 2026) found that mimicking real behaviour held the best attacker to 33.5% balanced accuracy at 100% overhead, while synthetic injection at the same overhead stayed at 93.9% [S34]. Older query-obfuscation work agrees: TrackMeNot noise was separable by semantic clustering [S29].
2. **Synthetic or scripted traffic is learnable.** Models trained on scripted browsing fell under 10% accuracy on human traces, while LLM-persona-generated traffic reached the 80% range [S40]. Distinguishing noise from a user is easier than the product's six-feature Naive Bayes self-test can show.
3. **Encrypted DNS and ECH do not end profiling.** Padding alone does not stop DNS traffic analysis [S22, S23]; destination-IP sets still identify sites (84% of 200K sites) [S25]; DoH/3 is fingerprintable (88.05% closed world, 449 classes) [S24].
4. **Browsing habits identify people.** The four most-visited domains identified 95% of individuals [S45]. Noise cannot erase habit; it must dilute and imitate it.
5. **Evaluation matters.** Realism checks cut some attack numbers (30-40% under real distribution shift [S14]; lower PR-AUC at realistic base rates [S18]), but a 2026 guard-vantage study still reports 0.956 precision / 0.922 recall at a 9% base rate [S11]. Do not assume attackers are weak; the self-test needs low-FPR, base-rate, drift and stronger-model metrics.

**Top feature ideas:** (1) adversary-grade self-test v2, (2) page-shaped DNS bursts, (3) HTTP-lane parity (the lane uses Python `requests`), (4) fingerprint-consistency auditor, (5) habit/revisit calibration from the baseline.

---

## 2. Adversary landscape

| Attack | What it needs | Reported strength (author-reported) | Key sources |
|---|---|---|---|
| Website fingerprinting (WF), Tor/VPN, classical features (k-FP, CUMUL) | Local passive view of one user's encrypted flows; labelled training crawls | Foundational; superseded by DL. Not re-verified this session | Survey [S1] |
| WF, deep learning (DF, Var-CNN, Tik-Tok) | Same, plus GPU training | DF >98% closed world on undefended Tor; open world 0.99 precision / 0.94 recall; WTF-PAD 0.96 / 0.68; Walkie-Talkie held it to 49.7% (2018) [S2]. Tik-Tok adds timing: 98.4% undefended, 93.5% on WTF-PAD (2019) [S3]. Var-CNN: lower FPR with little data (2018) [S4] | S2-S4 |
| WF vs. modern defenses | Defense-aware training | WFCAT: >59% vs. Surakav, +28 pts over RF (2024) [S5]. Order-aware 95k-parameter CNN: 54.2% vs. FRONT, versus 38.5% for a k-FP-style RF (2026) [S6] | S5, S6 |
| WF, multi-tab, fine-grained pages, zero-shot | Multi-label models, transformers | ARES (transformer, multi-tab, 2025) [S7]; DEMUX P@5 0.943 closed world 5-tab (2026) [S8]; Oscar Recall@5 +88.6% vs. prior (2024) [S9]; STAR zero-shot 87.9% top-1 on 1,600 unseen sites, works through ECH/encrypted DNS settings (2025) [S10] | S7-S10 |
| WF realism and base rate | Measurement-grade data | Guard-relay study on 800k+ real Tor traces: best attack 0.956 precision / 0.922 recall at 9% base rate, robust to jitter and drift (2026) [S11]. GTT23, genuine Tor traces dataset (2024) [S12]. Earlier critique: attacks fail at low base rate unless tuned for precision; precision-optimised classifier reached 0.78 at base rate 1e-5 (2018) [S13]. Systematic multi-condition evaluation shows many attacks degrade when conditions combine (2025) [S36] | S11-S13, S36 |
| Traffic-classification generalisation | Cross-network data | Under real distribution shift best solutions only 30-40%; 1-NN close behind (2025) [S14]. SoK: most encrypted-classifier papers used legacy data that was effectively unencrypted (2025) [S15] | S14, S15 |
| End-to-end / flow correlation (DeepCorr, DeepCoFFEA family) | Observation at both ends of a path | DeepCorr: 96% accuracy from ~900 packets (2018) [S16]. RECTor: up to 60% higher TPR under noise or partial observation vs. DeepCorr/DeepCoFFEA (2025) [S17]. InstantCoFFEA: 14.56x faster; PR-AUC 0.53 vs. 0.42 at realistic low base rates (2026) [S18] | S16-S18 |
| Coarse NetFlow telemetry | Sampled flow records (1-minute, 1:1000 sampling) | Active deanonymisation of Tor onion services from NetFlow-style counts (2026) [S19]. Older: NAT'd users fingerprinted from NetFlow alone, >90% accuracy (2014) [S20] | S19, S20 |
| Encrypted-DNS traffic analysis | On-path view of DoT/DoH | Domain identification with 124x less data than HTTPS WF; standard padding ineffective (2019) [S22]. Size plus timing defeat padding; need to remove inter-arrival entropy (2019) [S23]. App identification, up to 72% with padding (2021) [S21]. DoH/3 WF: 88.05% closed world / 0.975 AUPRC open world (2026) [S24] | S21-S24 |
| IP-set fingerprinting despite DoH+ECH | Destination IPs only | 84% of 200K sites identified, 92-95% for popular sites, ~70% after two months (2021) [S25] | S25 |
| SNI / ECH status | Handshake visibility | Firefox on by default since v119 (Oct 2023) per Mozilla FAQ; Cloudflare default-on for free zones; Chrome ~117/118 by differing sources; ECH needs DNS HTTPS records and uneven server deployment is a known concern [S26, S27, S28] | S26-S28 |
| TLS/QUIC client fingerprinting (JA3/JA4) and bot detection | Server or on-path view of ClientHello | Chrome extension-order randomisation broke JA3; JA4 sorts lists to survive it [S41, S42]. JA4 + gradient boosting separated bots from real clients, AUC 0.998 (2026) [S43]. LLM web agents separable at network, HTTP and browser layers; stealth tweaks often increase detectability (2026) [S44]. Evasive bots leak via attribute inconsistencies; rules cut evasion by 45-48% (2024) [S46] | S41-S46 |
| QUIC early-packet WF | Visible early QUIC packets | GQUIC/IQUIC 95.4-95.5% from only 40 packets, vs. 60.7% for HTTPS (2021) [S47] | S47 |
| App/video-streaming fingerprinting | Bitrate-shape of streams | Video title identification from encrypted DASH traffic via metric learning, scales to >1000 videos (2024) [S48]; datasets [S49] | S48, S49 |
| LLM-chat side channels | Packet size/timing of streamed replies | Whisper Leak: topic inference, often >98% AUPRC across 28 LLMs, high precision at 10,000:1 noise-to-target; mitigations (padding, batching, injection) reduce but do not eliminate (2025) [S50]. Token-length side channel reconstructs 29% of responses, topic 55% (2024) [S51]. Timing attacks on efficient inference (2024) [S52] | S50-S52 |
| Behavioural profiling and linking | Domain-level visit logs (ISP, DNS, broker) | Four most-visited domains identify 95% of individuals; 80% re-identified across contiguous time slices (2025) [S45]. Graph-based cross-device tracking from IP/domain histories (2022) [S53]. Profiling attacks on sparse behavioural data, 79% identification (2022) [S54]. Topics-style interest disclosure re-identifies 57-75% of stable-interest users after 15-30 epochs (2023) [S55] | S45, S53-S55 |
| Evaluation methodology pitfalls | n/a | Closed vs. open world, low base rate, drift, dataset realism: see [S11, S13, S14, S15, S36]. Information-theoretic leakage estimators (WeFDE, DeepSE-WF) [S35, S56]. Multi-class leakage cannot be driven to zero by any defense tested [S57] | S11, S13-S15, S35, S36, S56, S57 |

**Reading for this product.** legalPrivacy does not need to defeat WF on Tor. Its adversary is a bulk observer (ISP, DNS resolver, platform, broker) building a profile from domains, timing, volume and device signals, plus a classifier that tries to separate noise from the user. The most relevant rows are DNS, IP-set, behavioural profiling, bot/TLS fingerprinting, LLM side channels and the evaluation rows.

---

## 3. Defense landscape

| Defense | Idea | Overhead (author-reported) | Effectiveness (author-reported) | Sources |
|---|---|---|---|---|
| WTF-PAD / adaptive padding | Fill statistically expected gaps with dummies | 0 latency, <60% bandwidth (2016) | 91% to 20% closed-world accuracy vs. then-best attack; later broken by DF [S2] | [S58], [S2] |
| Tamaraw / Walkie-Talkie | Constant-rate regularisation / half-duplex bursts molding | Walkie-Talkie 31% bandwidth, 34% time (2017) | Walkie-Talkie held DF to 49.7% [S2]; Tamaraw is the high-security baseline | [S59, S60] |
| FRONT | Randomised dummies concentrated at trace start, zero delay | ~33% data | Beat WTF-PAD at similar overhead (2020); still 54.2% attacked by order-aware CNN (2026) [S6] | [S61, S6] |
| RegulaTor | Regularise to common download-surge pattern | 39.3% less bandwidth than leading moderate defense | Tik-Tok 66% to 25.4% closed world (2020) | [S62] |
| Surakav | GAN-generated sending patterns | ~50% less data/time than Tamaraw | Attacker TPR 8% (heavy), evaluated on live Tor (2022) | [S63] |
| TrafficSliver / Conflux | Multipath splitting | Bandwidth and latency cost | Guard with latency advantage still reaches high attack effectiveness under Conflux (2026) [S11] | [S11] |
| Maybenot | Probabilistic state machines scheduling padding/blocking (Rust) | Defense-specific | Framework (2023); evaluation says FRONT/RegulaTor/Surakav implementable but long-term suitability uncertain [S64, S65]. Mullvad "DAITA" reportedly integrates it (secondary report, unverified) | [S64, S65] |
| Adversarial perturbation (Mockingbird, Dolos, DeTorrent, TrapFlow) | Optimise padding against classifiers | Mockingbird 58% bandwidth (98% to 42-58% under adversarial training, 2019); Dolos 94+% protection, secret-parameterised patches (2021); TrapFlow RF 99% to 6% at 74% data overhead (2024); DeTorrent -61.5% closed-world accuracy, FC TPR ~0.12 at 1e-5 FPR (2023) | Defense-aware attackers erode static schemes; Chameleon (many-to-many morphing, 2026) argues most defenses create learnable mappings and shows defense-aware autoencoder attacks beat adversarially trained defenses | [S66-S70, S71] |
| Padding-only is not delay-free | Network-wide deployment adds queueing delay | n/a | Shadow simulations (2022) | [S72] |
| Application-layer HTTP/2 defenses | Emulate FRONT/Tamaraw with HTTP/2 features | Per defense | Under study (2026) | [S73] |
| Provable-style clustering | (k,l)-diverse anonymity sets plus Tamaraw | Adaptive Tamaraw cuts overhead up to 99% vs. Tamaraw | Bound on attacker accuracy <30% in high-privacy mode (2025) | [S74] |
| Flow-correlation defense | Egress connection shuffling and splitting | MUFFLER 2.17% bandwidth | TPR 1% at FPR 1e-2 (2025) | [S75] |
| Query obfuscation (TrackMeNot) | Cloud of fake searches | Low | Early design could resist bot detection (2011) [S28b]; clustering by semantic relatedness separated noise from real queries (2012) [S29] | [S28b, S29] |
| Modern query obfuscation | Random multilingual queries | Low | Search engine's inferred interests shifted and old profiles could be overwritten (Seznam.cz, 2025) | [S30] |
| DNS query forgery | Dummy queries optimised by KL divergence to a target profile | 50% privacy gain under 20% extra traffic; ~100% protection needs ~40-60% extra (2025) | Synthetic user traces; DNS profiles | [S31]; energy cost study [S32] |
| Adaptive fake-query count | Scale fakes by query sensitivity | n/a | CYCLOSA (SGX-based, 2018) | [S33] |
| Cover traffic by behavioural mimicry | Donor replay of real device traffic | 100% bandwidth | 33.5% vs. 93.9% for synthetic at equal overhead (2026) | [S34] |
| Mixnets (Loopix, Nym) | Poisson mixing plus cover loops | Seconds of latency | Strong against a global observer, but needs a mix network; simulator [S77]; parallel-mixnet analysis (2026) [S78] | [S76-S78] |
| LLM-chat mitigations | Random padding, token batching, packet injection | n/a | Reduce, not eliminate (2025) | [S50] |
| Synthetic realistic users | LLM multi-agent persona browsing | 3-5x cheaper than human collection | Scripted-trained models <10% on humans; LLM-generated ~80% (2025) [S40]. Caveat: prompt-only LLM agents hit only 11.86% action accuracy on real shopping sessions [S39] | [S38-S40] |
| Distinguishability metrics | Classifier two-sample tests, MMD, 1-NN | n/a | C2ST and kernel MMD / 1-NN tests are standard distance tools [S79, S80]; MI estimators [S35, S56] | [S35, S56, S79, S80] |

**Transferable to a user-run generator.** Behavioural realism, imitating the user's own distributions, coherent topics, stack parity and measurement. Not transferable without infrastructure: padding or morphing the user's own flows (needs a cooperating proxy or relay), mixnets, and most Tor-specific defenses.

---

## 4. Gaps vs. legalPrivacy

| Area | What legalPrivacy has | Gap (evidence) |
|---|---|---|
| Self-test model | Naive Bayes on six per-request features (hour, weekday, gap, popularity, revisit, ending); AUC with bootstrap CI; per-feature advice | No sequence/session features, no DNS-burst or flow-shape features, no stronger model, no TPR at 0.1-1% FPR, no base-rate precision, no time-split drift (S13, S36, S14). The classifier is far weaker than the attacker class in S5-S8, S43 |
| Where the NB is fooled | n/a | A cross-validated random split leaks temporal structure; a forward-in-time split is the honest test (S14, S15) |
| HTTP lane | `transports.py` uses Python `requests` | Distinct TLS and header ordering; JA4 plus GBM separates bots (AUC 0.998, S43); agent/bot layers separable (S44). Likely the single most distinguishable lane to a server, and a network observer sees the JA4 |
| DNS noise | Raw crafted UDP lookups (A, plus AAAA/HTTPS for browser mode), resolver mix, integrity checks | Standalone lookups do not look like page-load bursts; DoH traffic analysis relies on burst structure, size and timing (S21-S24). Subresource-domain sets also matter for IP-set fingerprints (S25) |
| Identity mix | Mobile/desktop identity, UA mixing, client hints | Mobile identities appear to be desktop Chromium/Firefox contexts with device emulation (browser.py `new_context` per device; verify); inconsistency across attributes (UA vs TLS vs hints vs viewport) is the main way evasive bots are caught (S46); stealth tweaks can raise detectability (S44) |
| Session state | Cookie jar load/save exists in browser.py | Persona-level persistence (cache warmth, consent state, repeated visitor behaviour) not evidenced; "absent cookies/history" is a known distinguisher class |
| Habit modelling | My List, personas, "keeps coming back" sessions, `revisit` metric | Habit is the strongest identifier (S45); no calibration of revisit/loyalty distributions to a measured baseline beyond the self-test advice string |
| Rhythm | Diurnal curve, bursts and gaps, drift/blend/alternate | Weekly structure only through the `weekday` feature; no per-user hour-of-week fit or burst/gap distribution fit to HAR baseline (baseline.py has the data) |
| Search noise | Engine queries, click-throughs, topics from feeds | Semantic coherence of query streams (clustering separated TrackMeNot noise, S29) not measured; no coherence test in the self-test |
| LLM chat noise | duck.ai sessions | Streamed-reply size/timing leaks topic (S50, S51); noise chats should be persona-coherent with varied length. Third-party service terms apply |
| Multi-tab / overlap | Sequential visits | Real users overlap loads; adversary models now handle multi-tab (S7, S8) so overlap with the user's own traffic can hide segmentation |
| Tor lane | Onion-only noise | Fine for the stated goal; flow correlation is not defeated by user-side cover and is out of scope (S16-S18) |
| Measurement of DNS and flow shape | psutil connection counters; HAR import | Counters give per-connection counts, not byte/packet shape; flow-level features would need a local capture (permissions) |

---

## 5. Ranked feature ideas

Effort: S small, M medium, L large. Value: how much it moves the realistic adversary result. "Quick win" = low effort, high value.

| # | Idea | Defends against | Effort / value | Overhead | Main risk |
|---|---|---|---|---|---|
| 1 | **Self-test v2: adversary-grade evaluator** (quick win) | Overconfidence in the current score | S-M / High | None on the network; some CPU | Over-fitting to the metric |
| 2 | **Page-shaped DNS bursts** (quick win) | DoH/DNS traffic analysis, subresource-domain sets | S-M / High | Small, replaces some standalone lookups | Wrong burst shape is itself a tell |
| 3 | **HTTP-lane parity** (quick win) | TLS/JA4 and header-order bot detection | M / High | None, may reduce volume | Browser-lane cost (CPU, bytes) |
| 4 | **Fingerprint consistency auditor** (quick win) | Attribute-inconsistency detection | S-M / High | None | Maintenance as browsers change |
| 5 | **Habit and revisit calibration from baseline** | Behavioural re-identification | M / High | None | Copying real habit too closely |
| 6 | **Weekly rhythm fit from HAR baseline** | Timing/diurnal profiling | S-M / Medium | None | Baseline may itself be unrepresentative |
| 7 | **Persistent persona state (returning visitor)** | "No cookies/history" and cold-cache distinguishers | M / Medium | Slight (cache saves bytes) | Cross-persona leakage, storage hygiene |
| 8 | **Search narrative coherence (optional local model)** | Semantic clustering of query noise | M-L / Medium | Compute only | Sensitive-topic safety, query ToS |
| 9 | **Chat-noise shaping for duck.ai** | LLM-chat side channels, topic inference | S / Low-Medium | Small | Third-party ToS, rate |
| 10 | **Co-activity overlap mode** | Flow segmentation, multi-tab-aware attackers | M / Medium | Slight | Slows the user's own browsing |
| 11 | **Closed-loop auto-tuner** | Drift between user behaviour and plan | M / Medium | None | Oscillation, over-fitting (needs #1) |
| 12 | **Offline benchmark kit with public datasets** | Unknown flow-level realism | M / Medium | None | Large downloads, licensing |
| 13 | **Stack-parity with the user's real client** (ECH, QUIC, HTTP/3, DoH) | Noise as the only odd client stack | M / Medium | None | Browser flags and versions |
| 14 | **Cross-device linking test** | GraphTrack-style IP/domain linking | M / Low-Medium | None | Measurement only |

### Details

**1. Self-test v2.** *Defends against:* a self-test that is easier to pass than a real adversary (S5-S8, S13, S36, S43).
Needs: nothing new. Sketch: in `legalprivacy/selftest.py` add (a) session features (n requests in last 5/30 min, distinct-domain ratio, run length, burst index), (b) a gradient-boosted or logistic baseline alongside Naive Bayes (scikit-learn optional dependency), (c) forward-in-time split (train on earlier days, test on later), (d) TPR at FPR 1% and 0.1% and precision at 1% and 0.1% base rate, (e) per-lane AUC. Report the worst of NB and the stronger model as the headline. Overhead: none on the network. Risk: more optimistic scores from weak models are the thing being removed. Measure: compare the NB AUC to the stronger-model AUC; the gap is the hidden leakage.

**2. Page-shaped DNS bursts.** *Defends against:* S21-S25. Needs: a list of real subresource domains per site (observed from browser lane via `page.on("request")` hostnames, kept in memory only). Sketch: when the browser lane loads a page, the resolver mix already sees the lookups. For the DNS-only lane in `scheduler._dns_probe` / `dnsplan.py`, replace independent single-name lookups with a burst: primary name, then 3-30 related names, spaced by a log-normal gap and with A/AAAA/HTTPS ordering like a browser. Cost: small. Risk: a burst shape that differs from the user's own DoH shape stays a tell. Measure: add DNS-flow features (burst size, inter-arrival, query-type mix) to selftest v2 and report AUC per lane.

**3. HTTP-lane parity.** *Defends against:* S43, S44, S46. Needs: either route all user-visible hits through the real browser lane, or use a browser-impersonating TLS/HTTP client (not evaluated in this survey). Sketch: in `transports.py`, keep the plain lane for non-web-like roles only (feeds, package-manager noise which really use non-browser clients), and move page-like HTTP hits into the browser lane or cap their share. Measure: a loopback self-hosted test page that logs ClientHello JA4-style hash and header order per lane; compare to the real browser.

**4. Fingerprint consistency auditor.** *Defends against:* S46, S44. Sketch: new `legalprivacy/consistency.py` that, per identity, checks UA vs client hints vs platform vs viewport vs locale vs timezone vs TLS engine (a desktop browser claiming mobile has desktop TLS; report it), run at start-up and shown on the Health tab. Fix: pair mobile identities with matching engine behaviours where possible; otherwise reduce their weight. Measure: auditor results plus the existing leak check.

**5. Habit and revisit calibration.** *Defends against:* S45, S54. Sketch: from `baseline.py` (HAR or history) compute the user's Zipf exponent for domain visits, share of repeat visits per day, and top-k concentration; feed those targets into `interests.py` and `scheduler.py` My List sampling and the "keeps coming back" sessions. Note that noise cannot remove the user's real top domains, only dilute them with a plausible parallel habit. Measure: self-test `revisit` and `popularity` AUC, plus a top-k overlap statistic.

**6. Weekly rhythm fit.** *Defends against:* timing/diurnal profiling. Sketch: in `rate.py`/`pacing.py` replace the single diurnal curve with a 168-bin hour-of-week table learnt from the baseline; also fit burst and gap length distributions (observe.py already computes `runs`). Measure: `hour`, `weekday`, `gap` AUC and observe.py KS similarity.

**7. Persistent persona state.** *Defends against:* cold-session tells. Sketch: per persona storage state (cookies, localStorage, consent choices) already partly handled by `browser.py` `_load_jar`; extend so a persona's revisits warm the cache and skip consent walls. Keep strictly separate from the user's real profile. Measure: bytes-per-visit and request-count distributions, new features in selftest v2.

**8. Search narrative coherence.** *Defends against:* S29, S30. Sketch: in `queries.py`/`interests.py` generate follow-up queries from the previous result title rather than independent draws; optional small local model for natural phrasing. Add a semantic coherence test to the self-test (cluster query embeddings, test separability between real and noise queries when the user supplies their own search history). Risk: topic safety; keep the existing topic filter and exclude sensitive categories by default.

**9. Chat-noise shaping.** *Defends against:* S50, S51. Sketch: in the duck.ai session code, draw prompt length, number of turns and gaps from heavy-tailed distributions, keep topics persona-coherent. Honest limit: this cannot hide the user's own chats; it only adds plausible decoys. Check duck.ai terms before raising frequency.

**10. Co-activity overlap mode.** *Defends against:* S7, S8 style segmentation. Sketch: use `observe.py` user-activity detection to start noise page loads during, not only between, the user's active periods, with a hard cap. Measure: gap/burst features in selftest v2.

**11. Closed-loop auto-tuner.** Sketch: `mixnudge.py` already nudges the mix; let it adjust within bounds from self-test v2 per-feature AUC, with hysteresis. Depends on #1 so it does not overfit Naive Bayes.

**12. Offline benchmark kit.** Sketch: `tools/` scripts that fetch CESNET-TLS-Year22 (S81) and CESNET-QUIC22 (S82) and DoH datasets (S83) for developer-side calibration of flow-level feature distributions; never shipped to users. Check licences first.

**13. Stack parity.** Sketch: detect which of ECH, HTTP/3 and DoH the user's real browser uses (from HAR or profile prefs) and align the noise browsers; relates to `realfirefox.py`. ECH status per S26-S28.

**14. Cross-device linking test.** Sketch: measure Jaccard overlap of domain sets and IP-time co-occurrence between the user's devices and noise identities (S53). Measurement only; informs `household.py`.

---

## 6. What NOT to do

| Do not | Why (evidence) |
|---|---|
| Add volume of random or uniform noise | Synthetic noise at equal overhead was far easier to classify than behavioural mimicry (S34); TrackMeNot noise clustered apart (S29) |
| Use a distinct HTTP client for web-like hits | Distinct JA4/header stack is a strong, cheap bot signal (S43) |
| Layer on stealth patches and random attribute spoofing | Inconsistent attributes and stealth add-ons raised detectability (S44, S46) |
| Copy the user's real top sites exactly at higher rates | Makes the user's habits more salient to a profiler (S45); use dilution and parallel habits instead |
| Rely on encrypted DNS or ECH as a stopping point | Padding is insufficient (S22, S23), IP sets and DoH/3 remain fingerprintable (S24, S25) |
| Trust a single self-test AUC from a weak model | Attackers use much stronger models and low-FPR metrics (S5-S8, S13) |
| Touch third-party accounts without explicit consent, post, like, send or purchase | Out of scope and a harm risk; signed-in visits stay read-only and manual sign-in |
| Fire searches on sensitive or legally risky topics | Harm and legal risk to the user; keep the topic filter |
| Run noise at levels that look like abuse to one site | Rate caps (engines.py already caps per-engine hourly volume) |
| Run Tor for ordinary web noise | Current design (onion only) avoids burdening Tor and making the user stand out |
| Claim protection from correlation attacks | User-side cover does not stop end-to-end correlation (S16-S18) |

---

## 7. Unverified / could not confirm

- Mullvad DAITA using Maybenot: appeared only in a search-result summary; not opened.
- Exact Chrome ECH default-on version and date: sources disagree (S26-S28).
- Original k-FP and CUMUL papers, DeepCoFFEA original paper, TrafficSliver, and Tor's own Maybenot/Arti announcements: not opened this session, so no numbers are stated for them.
- Walkie-Talkie's overhead and Tamaraw's characterisation are from search summaries of the USENIX/CCS pages; I did not read the full papers.
- FRONT's 33% overhead and Surakav's "50% less" and "8% TPR" come from search summaries of USENIX/IEEE pages, not the full text.
- Whether browser-impersonating HTTP clients indeed match browser JA4 and header order: not tested here.
- Real-world prevalence of ISP/broker use of the specific attacks above: not established by these sources; they are research results.
- Several 2026 arXiv entries were seen only as abstracts and are not peer-reviewed; treat as preliminary.

---

## 8. Reference list

Links are those returned by search this session (abstract pages unless noted).

**Website fingerprinting and defenses**
- [S1] Cui et al., WF attacks and defenses in Tor survey, 2025/2026. https://arxiv.org/abs/2510.11804
- [S2] Sirinam et al., Deep Fingerprinting, 2018. https://arxiv.org/abs/1801.02265
- [S3] Rahman et al., Tik-Tok, 2019. https://arxiv.org/abs/1902.06421
- [S4] Bhat et al., Var-CNN, 2018. https://arxiv.org/abs/1802.10215
- [S5] Gong et al., WFCAT, 2024. https://arxiv.org/abs/2412.11487
- [S6] Xu et al., Local Order Matters, 2026. https://arxiv.org/abs/2611.19864
- [S7] Deng et al., ARES multi-tab WF, 2025. https://arxiv.org/abs/2501.12622
- [S8] Yuan et al., DEMUX, 2026. https://arxiv.org/abs/2604.15677
- [S9] Zhao et al., Oscar fine-grained webpage fingerprinting, 2024. https://arxiv.org/abs/2409.04341
- [S10] Cheng et al., STAR zero-shot HTTPS WF, 2025. https://arxiv.org/abs/2512.17667
- [S11] Shadbeh, Khajavi, Wang, Reality Check for Tor WF in the Open World, 2026. https://arxiv.org/abs/2603.07412
- [S12] Jansen, Wails, Johnson, GTT23 genuine Tor traces, 2024. https://arxiv.org/abs/2404.07892
- [S13] Wang, Optimizing Precision for Open-World WF, 2018. https://arxiv.org/abs/1802.05409
- [S14] Akbari et al., traffic classification generalizability, 2025. https://arxiv.org/abs/2507.06430
- [S15] Wickramasinghe et al., SoK encrypted traffic classifiers, 2025. https://arxiv.org/abs/2503.20093
- [S36] Deng et al., realistic evaluation of WF attacks, 2025. https://arxiv.org/abs/2510.14283
- [S35] Li, Guo, Hopper, Measuring information leakage in WF, 2017. https://arxiv.org/abs/1710.06080
- [S56] Veicht, Renggli, Barradas, DeepSE-WF, 2022. https://arxiv.org/abs/2203.04428
- [S57] Liu et al., Inevitability of encrypted traffic side-channel leakage, 2026. https://arxiv.org/abs/2609.06322
- [S37] Bahramali et al., NetAugment/NetCLR, 2023. https://arxiv.org/abs/2309.10147

**Flow correlation and flow telemetry**
- [S16] Nasr et al., DeepCorr, 2018. https://arxiv.org/abs/1808.07285
- [S17] Wu et al., RECTor, 2025. https://arxiv.org/abs/2512.00436
- [S18] Hong et al., InstantCoFFEA, 2026. https://arxiv.org/abs/2611.28653
- [S19] Lee et al., NetFlow-based deanonymization of onion services, 2026. https://arxiv.org/abs/2610.15198
- [S20] Verde et al., NAT'd users from NetFlow, 2014. https://arxiv.org/abs/1402.1940
- [S75] Seo et al., MUFFLER, 2025. https://arxiv.org/abs/2504.07543

**DNS, SNI/ECH, TLS**
- [S21] Mühlhauser et al., Segram, 2021. https://arxiv.org/abs/2106.14058
- [S22] Siby et al., Encrypted DNS to Privacy?, 2019. https://arxiv.org/abs/1906.09682
- [S23] Bushart, Rossow, Padding Ain't Enough, 2019. https://arxiv.org/abs/1907.01317
- [S24] Zhang et al., DoHFuse (DoH/3 WF), 2026. https://arxiv.org/abs/2606.24105
- [S25] Hoang et al., IP-based website fingerprinting, 2021. https://arxiv.org/abs/2102.08332
- [S26] Mozilla ECH FAQ. https://support.mozilla.org/kb/faq-encrypted-client-hello
- [S27] CDT, The dynamics of the ECH rollout. https://cdt.org/insights/do-not-stick-out-the-dynamics-of-the-ech-rollout/
- [S28] SANS ISC, ECH: Ready for Prime Time? (2026-03-09). https://isc.sans.edu/diary.html?date=2026-03-09
- [S41] FoxIO JA4 technical details. https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- [S42] Fastly, Chrome ClientHello permutation. https://fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild
- [S43] Jarad, Bicakci, JA4 bot detection, 2026. https://arxiv.org/abs/2602.09606
- [S44] Fayolle et al., Unmasking web agents, 2026. https://arxiv.org/abs/2606.30119
- [S46] Venugopalan et al., FP-Inconsistent, 2024. https://arxiv.org/abs/2406.07647
- [S47] Zhan et al., WF on early QUIC, 2021. https://arxiv.org/abs/2101.11871
- [S84] Lyu et al., Survey on DNS encryption, 2022. https://arxiv.org/abs/2201.00900

**Streaming, LLM side channels, behaviour profiling**
- [S48] Gansekoele et al., video streaming deep metric learning, 2024. https://arxiv.org/abs/2405.09902
- [S49] Fesl et al., encrypted network video stream dataset (Data in Brief, 2023). https://doi.org/10.1016/j.dib.2023.109335
- [S50] McDonald, Bar Or, Whisper Leak, 2025. https://arxiv.org/abs/2511.03675
- [S51] Weiss et al., token-length side-channel, 2024. https://arxiv.org/abs/2403.09751
- [S52] Carlini, Nasr, remote timing attacks on LM inference, 2024. https://arxiv.org/abs/2410.17175
- [S45] Oliveira et al., Browsing behavior exposes identities on the Web, Sci Rep 2025. https://doi.org/10.1038/s41598-025-19950-3
- [S53] Wang et al., GraphTrack, 2022. https://arxiv.org/abs/2203.06833
- [S54] Tournier, de Montjoye, profiling attacks, Sci Adv 2022. https://doi.org/10.1126/sciadv.abl6464
- [S55] Beugin, McDaniel, interest-disclosing mechanisms, 2023. https://arxiv.org/abs/2306.03825

**Defenses**
- [S58] Juarez et al., Toward an efficient WF defense (WTF-PAD), 2016. https://arxiv.org/abs/1512.00524
- [S59] Cai et al., Tamaraw, CCS 2014. https://www.cs.uwaterloo.ca/%7Eiang/pubs/webfingerprint-ccs14.pdf
- [S60] Wang, Goldberg, Walkie-Talkie, USENIX Security 2017. https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao
- [S61] Gong, Wang, Zero-delay lightweight defenses (FRONT), USENIX Security 2020. https://www.usenix.org/biblio-3720
- [S62] Holland, Hopper, RegulaTor, 2020. https://arxiv.org/abs/2012.06609
- [S63] Gong et al., Surakav, IEEE S&P 2022. https://www.cse.ust.hk/~charlesz/papers/surakav.pdf
- [S64] Pulls, Witwer, Maybenot, 2023. https://arxiv.org/abs/2304.09510
- [S65] Witwer, State machine frameworks for WF defenses: Maybe not, 2023. https://arxiv.org/abs/2310.10789
- [S66] Rahman et al., Mockingbird, 2019. https://arxiv.org/abs/1902.06626
- [S67] Shan et al., Dolos, 2021. https://arxiv.org/abs/2102.04291
- [S68] Holland et al., DeTorrent, 2023. https://arxiv.org/abs/2302.02012
- [S69] Liang et al., TrapFlow, 2024. https://arxiv.org/abs/2412.11471
- [S70] Jing et al., Adversarial pre-padding vs. transformer classifiers, 2025. https://arxiv.org/abs/2510.25810
- [S71] Cui et al., Chameleon, 2026. https://arxiv.org/abs/2608.20160
- [S72] Witwer, Holland, Hopper, Padding-only defenses add delay, 2022. https://arxiv.org/abs/2208.02917
- [S73] Cebere et al., HTTP/2 against webpage fingerprinting, 2026. https://arxiv.org/abs/2609.05119
- [S74] Khajavi, Wang, Adaptive Tamaraw, 2025. https://arxiv.org/abs/2509.01046
- [S85] Gong et al., WFDefProxy, 2021. https://arxiv.org/abs/2111.12629
- [S86] Liu et al., Amoeba (RL against censorship classifiers), 2023. https://arxiv.org/abs/2310.20469
- [S87] Liu et al., NetMasquerade, 2025. https://arxiv.org/abs/2510.14906

**Cover traffic, obfuscation, mixnets**
- [S28b] Toubiana et al., TrackMeNot, 2011. https://arxiv.org/abs/1109.4677
- [S29] Al-Rfou et al., TrackMeNot-so-good-after-all, 2012. https://arxiv.org/abs/1211.0320
- [S30] Firc et al., random multilingual query obfuscation, 2025. https://arxiv.org/abs/2506.04963
- [S31] Jimenez-Berenguel et al., DNS query forgery, 2025. https://arxiv.org/abs/2505.09374
- [S32] Jimenez-Berenguel et al., dummy-query energy cost, Sensors 2026. https://doi.org/10.3390/s26206577
- [S33] Pires et al., CYCLOSA, 2018. https://arxiv.org/abs/1805.01548
- [S34] Alghamdi et al., game-theoretic Wi-Fi MAC-layer obfuscation, Sensors 2026. https://doi.org/10.3390/s26154690
- [S76] Piotrowska et al., Loopix, 2017. https://arxiv.org/abs/1703.00536
- [S77] Piotrowska, mix network simulator, 2021. https://arxiv.org/abs/2107.12172
- [S78] Ingo, Druschel, Garg, parallel mixnets, 2026. https://arxiv.org/abs/2611.22732

**Synthetic users and evaluation**
- [S38] Wang et al., LLM agent user behavior simulation, 2023. https://arxiv.org/abs/2306.02552
- [S39] Lu et al., Can LLM agents simulate multi-turn human behavior?, 2025. https://arxiv.org/abs/2503.20749
- [S40] Song et al., Redefining WF with multiagent LLMs, 2025. https://arxiv.org/abs/2509.12462
- [S79] Bischoff et al., sample-based statistical distances (C2ST, MMD), 2024. https://arxiv.org/abs/2403.12636
- [S80] Xu et al., evaluation metrics for GANs (MMD, 1-NN), 2018. https://arxiv.org/abs/1806.07755
- [S81] Hynek et al., CESNET-TLS-Year22, Sci Data 2024. https://doi.org/10.1038/s41597-024-03927-4
- [S82] Luxemburk et al., CESNET-QUIC22, Data in Brief 2023. https://doi.org/10.1016/j.dib.2023.108888
- [S83] Jeřábek et al., DoH traffic datasets, Data in Brief 2022. https://doi.org/10.1016/j.dib.2022.108310
