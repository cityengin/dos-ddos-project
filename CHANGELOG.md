# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- L7 mitigation (`mitigation/`): an nginx per-IP rate-limit config and a before/after demo
  (`mitigation/demo_mitigation.py`) that turns the IDS into IPS-style protection. In the lab a
  3-source HTTP flood drops from 30,430 to 240 served requests (~99% blocked) with no impact on a
  legitimate client. Optional permanent mount documented in `docker-compose.yml`.
- `detector.py --stream`: emit one JSON object per window to stdout (for the dashboard), keeping the
  existing human-readable table and CSV output unchanged.
- Local-only realtime dashboard (`dashboard/`, Node + Express + WebSocket): network-topology view,
  attack control (A/B/C scenarios), and an L7 defense toggle, all driven by the detector's live
  stream. Binds to 127.0.0.1 only; control actions are fixed `docker exec` argument arrays
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

### Changed

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

### Fixed

- Detector exits loudly if its packet sniff fails (e.g. after recreating only the victim, which
  breaks the `network_mode: service:victim` namespace) instead of silently streaming `pps=0`.
- Dashboard service-health probe runs over the victim loopback, so it no longer appears on the
  sniffed interface and inflates `n_src` — scenario A reads **DoS** again (not DDoS).
- Dashboard event log appends the newest entry at the bottom (chronological, terminal-style) and
  auto-scrolls only when already near the bottom, so reading history is not yanked down.

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
