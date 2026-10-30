# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **DoS-vs-DDoS classifier now uses source count _plus dominance_**, not a bare `n_src >= 2`. Adds
  `--ddos-min-src` (default 10) and `--ddos-dom-share` (default 0.8): a window is DDoS when
  `n_src >= --ddos-min-src` (many sources — spoof or many hosts) **or** (`n_src >= 2` **and** the top
  source's packet share `top_share < --ddos-dom-share` — no single source dominates); otherwise DoS.
  Fixes a real-shared-network misclassification: on campus WiFi a single-source DoS picks up 1–2 stray
  background packets to the victim each window, so the old `n_src >= 2` rule flagged it DDoS —
  `top_share ≈ 1.0` (and `H(src) ≈ 0`) shows it is really one source (measured: A non-spoof →
  `n=3, H(src)=0.03, top≈0.998`). The isolated Docker lab (only attacker+victim) is unaffected, so
  A/B/C there are unchanged. Adds `top=<share>` to the DoS/DDoS alert line; CSV / `--stream` / ML /
  `--adaptive` / `[SYN flood]` / `[UDP flood]` are all unchanged. Validated live on 2 real machines
  over WiFi: A→DoS, B(spoof)→DDoS, C(1 source)→DoS, D(UDP)→DoS.

### Added

- **PCAP-based window-dataset pipeline** for ML dataset collection, alongside the existing
  `build_window_dataset.py` (kept as a fallback). `detection/window_features.py` is a new single source
  of truth for the window feature formula, imported by both the offline extractor and (later) the live
  detector so they compute identical features; it defines `FEATURES` (10 live-supplyable: the 9 canonical
  + `rate_per_src = pps/max(n_src,1)`) and a broader `EXTRACT` set (adds `icmp_s`, `udp_ratio`,
  `avg_pkt_size`) written to the dataset for later pruning. `attacks/benign_gen.py` generates legitimate
  user traffic (randomized GETs, think-time, low rate) for a real BENIGN class (no longer labelling by
  `pps==0`). `experiments/capture_session.py` orchestrates a 14-phase scenario matrix in the Docker lab
  via `docker exec` (benign + flash-crowd, single-source DoS, spoofed DDoS, and real multi-source DDoS
  including an exact 2-source no-spoof mode that matches a future physical demo; diverse pps low/mid/high),
  runs `tcpdump -s 100` inside the detector container, and writes a host-clock timeline. `ml/pcap_to_windows.py`
  extracts sliding windows (1.0s / 0.5s stride) via the shared module and labels each window by the
  timeline (a window overlapping an attack interval gets that attack's class — "any attack packet in the
  window ⇒ attack", early-detection bias). `ml/train_window.py` now imports `FEATURES` from the shared
  module, **drops the random 70/30 split** (overlapping windows leak), evaluates only by
  leave-one-run-out (1 pcap = 1 run), and prints feature importance. `avg_pkt_size` is taken from the IP
  total-length header field so the `-s 100` snaplen does not corrupt it; `detection/Dockerfile` already
  ships `tcpdump`. The Docker lab, attack scripts, live detector, and scenarios A/B/C are unchanged.
- **`http_flood.py --pps`** — paces total requests/s across the worker threads (default `0` = unlimited,
  behaviour unchanged). Mirrors `syn_flood.py --pps` and lets the L7 capture scenarios be held to
  realistic packet rates instead of the Docker bridge's tens-of-thousands pps, so the ML dataset does not
  domain-shift away from a real 2-machine WiFi demo. `capture_session.py` uses it to pace H1 (~150 req/s),
  D2h (~150/source) and D5h (~120/source), lowers the benign floor to `--floor-pps 2` (~11 pps), and drops
  S1 to `--pps 12` so that single-source sub-threshold SYN (which doubles to ~2x pps via kernel RST
  reflection) stays under the 40 pps / 25 syn rule — the case the window ML should catch and the rule miss.
- **UDP flood** — a third attack type (volumetric L3/4), alongside SYN (L4) and HTTP (L7). New
  `attacks/udp_flood.py` mirrors `syn_flood.py` (scapy `IP()/UDP()`, `--spoof`, `--pps`, `--count`,
  `--size`, one reused `conf.L3socket()`). The detector now counts UDP in both engines (scapy
  `on_packet` gained a UDP branch; `ebpf_counter.py` surfaces the already-present `counters[3]`), adds
  a `udp_s` CSV column (after `ack_s`) and a `udp` field to the `--stream` JSON, and tags
  `[UDP flood]` when `udp_s >= --pps` and `udp_s > syn_s` (UDP dominates — so a mixed SYN+UDP window
  isn't mislabeled). `--engine`/`--block`/`--ml`/`--adaptive` and the DoS-vs-DDoS/`n_src`/entropy
  logic are unchanged; the ML window model and its 8 features are untouched (the dataset builder reads
  the CSV by column name, so the extra column is ignored). SYN/HTTP scenarios A/B/C produce identical
  output with `udp_s=0`. `udp` mode added to both orchestrators: `run_ddos.sh udp` (paced scapy, or
  `-i max` → `hping3 --udp --flood`) and `run_ddos_remote.sh udp` (which routes UDP through the same
  raw-socket privilege path as SYN — `CAP_NET_RAW` or `-s`/NOPASSWD — not HTTP's). Docs: a UDP
  scenario in `docs/MULTI_MACHINE.md` and `docs/TESTING.md`.
- **Multi-machine (physical) support** — run the lab on real Linux laptops over a shared private
  WiFi, additively (the Docker lab and every existing script are untouched). The attack scripts and
  `detection/detector.py` already take all addresses as parameters, so they run bare-metal unchanged
  (`--iface wlan0 --victim <dhcp-ip>`). Adds `run_ddos_remote.sh`, an SSH orchestrator that fires one
  or more real attackers in parallel via a repeatable `-a user@ip` flag (`timeout`-bounded, runs each
  over background SSH then `wait`s), with an SSH preflight check and a `-s` flag for the NOPASSWD-sudo
  path. Adds `docs/MULTI_MACHINE.md` (Vietnamese): 3-machine model, DHCP IP discovery, software to
  install, the A/B/C commands, the "2 machines now vs add a 3rd" note (C needs 2 real attackers to be
  a true DDoS), differences from Docker, and the `CAP_NET_RAW` (recommended, with a scope warning) vs
  NOPASSWD-sudoers options for the SYN flood's raw socket over SSH. README gains a "Multi-machine
  (physical)" section.
- **Max-intensity attack mode** (`intensity=paced|max`) alongside the paced default. `max` drives
  **line-rate** tools instead of the scapy/urllib scripts — `hping3 -S --flood` (SYN, `--rand-source`
  to spoof) and `ab -k -c 500` (L7) — for scenarios **A/B/C only**, and forces `--engine ebpf` (scapy
  can't count at line-rate). Wired into `experiments/run_scenarios.py` (`--intensity`, plus `--max-rate`
  to cap hping3 for a safe ramp and `--max-conc` for ab), `run_ddos.sh` (`-i paced|max`), and the
  dashboard (a **"Max intensity"** toggle). The paced path (scapy with rate limiting, used for the ML
  dataset) is unchanged. `ab` is added to the attacker image (`apache2-utils`).
- **Real-impact measurement** of the max floods (detect-only, no blocking), reported honestly in
  `PROJECT_STATUS.md` / `docs/`: A-max ~190k pps, B-max ~123k pps, C-max ~693k pps, with **zero eth0 rx
  drops** and a legit client staying **100% 200-OK** in every state (only C-max's p95 latency rises
  ~1→11ms). Modern defaults (kernel SYN cookies + fast static nginx) absorb all three; downing this
  victim would need a weaker target or far larger scale. With `--block` on, A-max is dropped ~100% at
  XDP and C-max collapses (~433k→~28 pps) with the latency tail back to ~1ms.
- The dashboard detector now **always runs the eBPF engine** (accurate at line-rate), so the new
  Max-intensity toggle needs no detector restart; `--block` is still added only when Blocking is on.
  `stopAttack`/`cleanup` now also kill `hping3`/`ab` (not just the `*_flood.py` scripts).
- Dashboard **Blocking ON/OFF** toggle and a `blocked/s` tile. Turning it on restarts the detector with
  `--engine ebpf --block --block-pps 200 --block-ttl 5 --block-syn-rate 2000`; the stream's
  `blocked_src`/`blocked_pps` are shown live. In the lab a 6-source HTTP flood's rate collapses
  (~15k → ~36 pps) once blocking engages. Off by default (detect-only). A `detStarting` guard serializes
  detector (re)starts so a toggle can't spawn overlapping detectors that kill each other.
- Detection-driven blocking (closed-loop IPS) via **eBPF `XDP_DROP`** (`detection/detector.py --block`,
  default off, requires `--engine ebpf`). The XDP program **counts first, then drops**: sources whose
  per-window rate exceeds `--block-pps` are added to a `blocklist` BPF map with a TTL (`--block-ttl`,
  auto-expiring — no permanent block) and dropped; `--block-syn-rate N` adds a global SYN token-bucket
  (`bpf_spin_lock`) that drops SYNs above `N`/s to handle spoofed floods where per-source blocking is
  useless. Reports `blocked_src`/`blocked_pps` in the table / `--stream` / `--csv`. Lab demo: a stateful
  HTTP flood (C) collapses from **~136k to ~242 pps** once its 6 sources are blocked; a spoofed SYN
  flood (B) is unaffected by per-source blocking but `--block-syn-rate 2000` drops **~85%** of it
  (trade-off: some legitimate SYNs dropped). Safety: TTL auto-expiry, bounded map, low-rate clients and
  the health probe stay under the threshold; `--block` is off by default so detect-only is unchanged.
- eBPF/XDP counting engine for the detector (`detection/detector.py --engine scapy|ebpf`, default
  `scapy`). `detection/ebpf_counter.py` (BCC) attaches an **XDP ingress** program to the victim's
  `eth0` that counts packets/syn/ack and per-source-IP / per-dest-port histograms into BPF maps and
  always returns `XDP_PASS` (**detect-only, never drops**); userspace reads and clears the maps every
  second. Both engines return the same per-window counters, so the rule, `--adaptive`, `--ml`,
  `--stream`, `--csv` are unchanged. The detector now builds from its own `detection/Dockerfile`
  (ubuntu + scapy + `python3-bpfcc`) and `docker-compose.yml` grants it `CAP_BPF`/`CAP_PERFMON`/
  `CAP_NET_ADMIN` + read-only mounts of `/lib/modules`, `/usr/src`, `/sys/kernel/debug`. On a
  120,000-packet high-rate flood the scapy engine observed only **57%** (peak ~6.9k pps, its
  processing ceiling) while the XDP engine observed **95%** and captured the true ~30k pps peak; at
  low rate both are exact (5,000-packet test: eBPF 4,986). Detect-only — no packets are dropped.
- SVG project banner (`banner.svg`), displayed at the top of the README.
- Adaptive EWMA thresholding in the detector (`--adaptive`): dynamic threshold
  `μ + k·MAD` with `--pps/--syn` as a floor, and baseline learning frozen during alerts.
- Synthetic fixed-vs-adaptive evaluation (`experiments/adaptive_eval.py`) and its figure
  (`assets/adaptive_eval.png`), showing adaptive catches an attack a fixed threshold misses
  while avoiding false positives on drifting legitimate traffic.
- Markdown theory guide (`docs/LyThuyet_DoS_DDoS.md`) for on-GitHub study, including the
  adaptive-threshold and state-of-the-art sections.
- Machine-learning pipeline (`ml/`): `train.py` trains RandomForest + HistGradientBoosting on
  flow features, compares against a single-threshold rule, and plots F1 / confusion matrix.
  `make_synthetic.py` generates a CICDDoS2019-style sample so it runs out of the box.
- `ml/train.py` reads large CSVs in chunks with size-estimated sampling and accepts a directory
  of files, so it scales to the full CICDDoS2019 flow data without exhausting memory.
- `detector.py --stream`: emit one JSON object per window to stdout (for the dashboard), keeping the
  existing human-readable table and CSV output unchanged.
- Local-only realtime dashboard (`dashboard/`, Node + Express + WebSocket): network-topology view
  (with a service-health probe) and attack control (A/B/C scenarios), all driven by the detector's
  live stream. Binds to 127.0.0.1 only; control actions are fixed `docker exec` argument arrays
  (no shell interpolation of client input).
- Testing & verification guide (`docs/TESTING.md`) covering every component with expected results.
- `ml/train.py` now reads **parquet** as well as CSV, and label canonicalization (`--raw-labels`
  to disable) that merges CICDDoS2019's dual `DrDoS_X`/`X` labels for the same attack family into
  one canonical family — the dataset labels the same families two ways across capture days.
- Scaled the lab to **6 attacker containers** (`attacker1..6`, IPs `.21..26`) so an L7/HTTP DDoS
  shows 6 real sources; `run_ddos.ps1` and `experiments/run_scenarios.py` drive all six.
- `attacks/syn_flood.py` reuses one `conf.L3socket()` (far faster than per-packet `send()`) and takes
  `--pps` to pace the send rate; spoofing at a high rate now reaches **n_src ~2300** distinct source
  IPs per window (H(src) ~11) instead of ~66.
- `run_ddos.sh`: Bash orchestrator for Linux (equivalent of the PowerShell `run_ddos.ps1`) that
  launches all six attackers in parallel for `syn`/`http` mode. Self-elevates through `sg docker`
  when the login session has not reloaded the `docker` group, so it runs without a prior re-login.
- `experiments/bench_syn_throughput.sh`: SYN packet-generation benchmark. Uses a two-point
  (short/long duration) measurement to cancel scapy start-up cost and reports per-source and
  aggregate pps for 1 and 6 sources — the number to compare host platforms with. On the Ubuntu
  native host it reaches **~1,470 pps per source** and **~9,460 pps aggregate** (6 sources), showing
  the paced scenario B (`--pps 400` ×6 = 2,400 pps) is pacing-limited, not hardware-limited.
- `experiments/run_scenarios.py`: `--pps` optionally overrides the per-source SYN rate for the SYN
  scenarios; backward-compatible (omit = keep the built-in rates). Two **near-threshold scenarios**
  were added to make the ML-vs-rule comparison non-trivial: **D** (low-rate spoofed SYN, 2 sources,
  ~24 pps total — below the 40/25 rule threshold, so the rule misses a real attack) and **E** (a
  benign single-source HTTP flash-crowd whose rate exceeds the threshold, so the rule false-alarms).
  HTTP scenarios take a `threads` field to set their rate; the effective pps is recorded in each
  scenario's `.meta.json`.
- `ml/build_window_dataset.py`: builds a **window-level** labeled dataset from the detector's own
  per-window features (the detector has window features, not the flow features CICDDoS2019 needs, so
  the live ML model is trained on these instead). It orchestrates repeated scenario runs (A/B/C plus
  the near-threshold D/E, varying duration/pps), labels each 1-second window `BENIGN` (pps==0) or the
  run's ground truth, adds derived features `syn_ratio` and `ack_syn_ratio`, records the originating
  `run` (for leave-one-run-out), and writes `ml/data/windows.csv` with a class-balance report. It
  warns loudly if any run yields 0 windows (a sign the detector sniff was disrupted). Lab dataset:
  316 windows (BENIGN 162 / DDoS 114 / DoS 40), with ~48% of attack windows below the rule threshold.
- `ml/train_window.py`: trains a single multiclass RandomForest (BENIGN/DoS/DDoS) on the detector's
  own per-window features and saves it to `detection/window_model.joblib` (bundled with feature
  order, label order and the sklearn version) for the detector to use live. It compares against the
  project rule (pps>=40 or syn>=25; n_src>=2 => DDoS) on a 70/30 split and with leave-one-run-out
  (binary F1 averaged only over folds that contain attack windows). The near-threshold D/E make the
  rule fail both ways (false negatives on D, false positives on E): attack-detection F1 is
  **0.58 (rule) vs 0.99 (RF)**, multiclass macro-F1 **0.59 (rule) vs 0.99 (RF)**; on attack windows
  below the rule threshold the rule catches **0%** vs the RF's **100%**; leave-one-run-out F1 is
  **0.52 (rule) vs 0.99 (RF)**. The RF is no longer perfect (it misses ~1 near-threshold window);
  pushing it lower would need a multi-source benign flash-crowd overlapping the HTTP-DDoS class.
- `detection/detector.py --ml PATH`: load a window-model `.joblib` (from `train_window.py`) at
  startup and classify every 1-second window with it **in parallel with the threshold rule**, so the
  table, `--stream` JSON (`ml_verdict`/`ml_conf`) and `--csv` (two extra columns, only when `--ml`)
  all show both verdicts. It fails loudly (exits) if the model/scikit-learn/joblib is missing or the
  bundle is malformed. The rule stays the default; `--ml` is additive. Verified live in the lab:
  baseline -> `BENIGN`, scenario A -> `DoS`, B/C -> `DDoS`; the first partial HTTP window (a single
  source, ACK-heavy) reads `BENIGN` at low confidence — the flash-crowd behavior learned from
  scenario E.
- `attacker/Dockerfile`: install `scikit-learn==1.9.1` + `joblib==1.6.0` (pinned to the training
  version) so the detector container can load the window model for `--ml`.
- Dashboard shows the **ML verdict beside the rule verdict**. The backend starts the detector with
  `--ml` when `detection/window_model.joblib` exists (rule-only otherwise) and relays `ml_verdict`/
  `ml_conf`; the Attack panel's verdict box now reads `rule: <X>` with an `ML: <Y> · <conf>%` line
  below it, colored green/amber/red by the ML verdict so a rule-vs-ML disagreement is visible at a
  glance. Styling reuses the existing tokens (no new colors).

### Changed

- Docs updated for the live-ML work: `README.md` (detector `--ml`, the window-ML pipeline, the
  dashboard's dual rule/ML verdict, and a Linux `run_ddos.sh` usage example), `docs/TESTING.md`
  (near-threshold scenarios D/E, a window-ML section, the dashboard ML line, refreshed checklist),
  and `docs/LyThuyet_DoS_DDoS.md` (new section 8.2 on ML trained on the detector's own features).
- Machine learning now runs on the **real CICDDoS2019** dataset (the cleaned parquet release
  `dhoogla/cicddos2019`, fetched via `kagglehub`) instead of only the synthetic sample. On ~131k
  flows / 63 features / 13 families, attack-detection F1 goes from **0.60** (single-threshold rule)
  to **0.999** (RandomForest; 0.996 HistGradientBoosting); family classification reaches **0.93**
  accuracy / **0.74** macro-F1. The synthetic sample stays as a zero-download fallback. Regenerated
  `assets/ml_f1_compare.png`, `assets/ml_confusion.png`, and `ml/results/metrics.txt`.
- Theory guide (`docs/LyThuyet_DoS_DDoS.md`): ML section updated to the real CICDDoS2019 results,
  plus a note explaining why the source count differs by layer (6 real containers for an L7 DDoS;
  L4 SYN spoofing reaches ~2300 source IPs).
- Dashboard: scenarios B/C relabelled to **6 sources** and the network view renders 6 attacker nodes;
  the event log moved **below the console (off-screen)** so it no longer takes space from the panels
  (scroll down to see it), which also stops the attack panel from being clipped. Scenario B/C attack
  commands now pace SYN with `--pps` (A 150, B 400 per source).
- Full pass over every `.md` file to match the current code and stay consistent across files:
  fixed the detector's build path (`./detection`, not `./attacker`) in README's architecture table;
  fixed a stale `attacker/Dockerfile` reference to the window-model ML deps (they live in
  `detection/Dockerfile`, the detector's own image) in the theory guide; fixed a leftover "3
  container" comparison (the lab has 6) in the theory guide's state-of-the-art table; resolved a
  numeric mismatch for scenario B between `docs/TESTING.md` and the other three files (pps/syn/
  n_src/H(src) now read ~4000/~2000/~2300/~11.1 everywhere); removed a stale "will rebuild
  mitigation later" TODO from `PROJECT_STATUS.md` left over from before closed-loop blocking
  shipped; `CLAUDE.md`'s host-environment line and command block now say Ubuntu native / bash
  (were Windows + Docker Desktop / PowerShell); README's Requirements, Usage, Detection Mechanism,
  Results, Dashboard, and Project Structure sections now cover the eBPF engine, closed-loop
  `--block`, max-intensity mode, and the dashboard's Blocking/Max-intensity toggles, none of which
  were documented there before.

### Fixed

- eBPF counter no longer stalls under a `--rand-source` SYN flood: the `src_ip` BPF hash is **capped at
  8192** entries (was 65536), bounding the per-window userspace read/clear (tens of thousands of distinct
  spoofed IPs/s previously froze window output). Packet/SYN/ACK counts (PERCPU) stay exact; only `n_src`
  saturates (~8192), which still reads unambiguously as a highly dispersed DDoS (`H(src)`≈13).
- Dashboard exit now stops the **in-container** detector (`docker exec detector pkill -f detector.py`),
  not just the local `docker exec` client. Previously, stopping `node server.js` left the detector
  running — and if blocking was on it kept dropping packets with its XDP program still attached, which
  also made standalone detector runs intermittently fail to attach XDP.
- The dedicated detector image (`detection/Dockerfile`) regained `scikit-learn==1.9.1` + `joblib==1.6.0`:
  the eBPF-engine rebuild moved the detector off the attacker image and silently dropped them, so
  `detector --ml` (and the dashboard's ML line) crashed with `No module named 'joblib'`.
- Detector exits loudly if its packet sniff fails (e.g. after recreating only the victim, which
  breaks the `network_mode: service:victim` namespace) instead of silently streaming `pps=0`.
- Dashboard service-health probe runs over the victim loopback, so it no longer appears on the
  sniffed interface and inflates `n_src` — scenario A reads **DoS** again (not DDoS).
- Dashboard event log appends the newest entry at the bottom (chronological, terminal-style) and
  auto-scrolls only when already near the bottom, so reading history is not yanked down.

### Removed

- `run_ddos.ps1` (the PowerShell orchestrator): the project now runs on Linux only, and
  `run_ddos.sh` (bash) has covered the same job since it was added. All active docs now reference
  `run_ddos.sh`; historical CHANGELOG entries about `run_ddos.ps1` are left as-is.
- L7 mitigation (nginx per-IP rate-limit): the `mitigation/` directory (`demo_mitigation.py`,
  `nginx/default.conf`), its figure, the dashboard Defense panel / toggle, and all docs references.
  Defense will be rebuilt as detection-driven blocking (closed-loop: the detector triggers the
  block) rather than a standalone rate-limit. The dashboard keeps the Service health probe (an
  impact indicator), moved into the Network panel.

## [1.0.0] - 2026-09-30

First tagged release. Captures the current state of the lab, attacks, detector, tooling, and docs.

### Added

- Isolated Docker lab (`docker-compose.yml`): `victim` (nginx), three attackers, and a
  `detector` that shares the victim's network namespace on `dos-lab` (`172.30.0.0/24`).
- Attacker/detector image (`attacker/Dockerfile`) with scapy, hping3, and tcpdump.
- SYN flood attack (L4) with optional IP spoofing (`attacks/syn_flood.py`).
- HTTP flood attack (L7), multi-threaded (`attacks/http_flood.py`).
- Real-time detector (`detection/detector.py`): per-second thresholds (`pps`, `syn/s`),
  Shannon entropy of source IPs, distinct-source classification (DoS vs DDoS), and a
  `[SYN flood]` tag based on the ACK/SYN ratio.
- Inbound-only counting (`--victim`) so the victim's own replies are not miscounted as a source.
- PowerShell orchestrator to run three attackers in parallel (`run_ddos.ps1`).
- Reproducible scenario runner for baseline + A/B/C with ground-truth metadata
  (`experiments/run_scenarios.py`).
- Guided one-command demo with Docker/container preflight checks and live detector streaming
  (`experiments/demo.py`).
- Analysis tools: timeline plots (`analysis/plot_attack.py`) and evaluation metrics —
  detection time, false positives/negatives, classification table (`analysis/metrics.py`).
- Finalized experiment dataset and figures used in the report (`results/final/`).
- Project documentation: `README.md`, theory document `TaiLieu_LyThuyet_DoS_DDoS.docx`,
  and internal status notes `PROJECT_STATUS.md`.
- Repository scaffolding: `.gitignore`, `CONTRIBUTING.md` (Conventional Commits + workflow),
  and an ASCII project banner (`banner.txt`) printed by the demo.

[Unreleased]: https://github.com/cityengin/dos-ddos-project/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cityengin/dos-ddos-project/releases/tag/v1.0.0
