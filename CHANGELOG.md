# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

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
