<p align="center">
  <img src="banner.svg" alt="DoS/DDoS Attack Simulation & Detection Lab — PBL3" width="100%">
</p>

# DoS/DDoS Attack Simulation & Detection Lab

A self-contained, Docker-based lab that **simulates** DoS/DDoS attacks and **detects and
classifies** them in real time. Built as an end-of-term project (DUT — PBL3).

The detector observes traffic in one-second windows and combines simple rate thresholds with
**Shannon entropy of source IPs** and **distinct-source counting** to tell a single-source
**DoS** apart from a multi-source **DDoS**, and an L4 **SYN flood** apart from an L7 **HTTP flood**.

---

## ⚠️ Disclaimer — Educational use only

This project is provided **strictly for education and defensive research inside a fully
isolated laboratory**. The attack scripts must only ever target the lab's own `victim`
container on the private `172.30.0.0/24` network.

- **Do NOT** point these tools at any host, network, or service you do not own or lack
  explicit written permission to test.
- Denial-of-service attacks against systems without authorization are **illegal** in most
  jurisdictions.
- The authors accept **no liability** for misuse. You are solely responsible for how you use
  this code.

---

## Table of Contents

- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Mechanism](#detection-mechanism)
- [Results](#results)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Development](#development)

## Overview

The project has two halves that run against each other in an isolated network:

1. **Attack side** — SYN flood (L4) and HTTP flood (L7) scripts, optionally with IP spoofing,
   driven from one to three attacker containers.
2. **Detection side** — a real-time sniffer that reports per-second traffic features and raises
   classified alerts (`DoS` / `DDoS`, with a `[SYN flood]` tag when applicable).

## Lab Architecture

![Lab architecture](assets/architecture.png)

All services share one isolated bridge network, `dos-lab` (`172.30.0.0/24`):

| Container   | Image / Build      | IP            | Role                                                        |
|-------------|--------------------|---------------|-------------------------------------------------------------|
| `victim`    | `nginx:alpine`     | 172.30.0.10   | Target web server, published to `localhost:8080`            |
| `attacker1` | `./attacker`       | 172.30.0.21   | Attack source (scapy + hping3), `NET_RAW` + `NET_ADMIN`     |
| `attacker2` | `./attacker`       | 172.30.0.22   | Attack source                                               |
| `attacker3` | `./attacker`       | 172.30.0.23   | Attack source                                               |
| `detector`  | `./attacker`       | shares victim | Sniffs the victim's `eth0` (`network_mode: service:victim`) |

The detector shares the victim's network namespace, so it sees exactly the traffic the victim
sees. Attack and detection scripts are **bind-mounted**, so edits take effect on the next
`docker exec` without rebuilding images.

## Requirements

- **Windows 10/11** with **Docker Desktop** (WSL2 backend). The lab is Linux-container based
  and also works on Linux/macOS with Docker.
- **Python 3.11+** on the host with **matplotlib**, for the analysis/plotting scripts only
  (everything else runs inside containers):

  ```bash
  pip install matplotlib
  ```

## Installation

```bash
git clone <your-private-repo-url> dos-ddos-project
cd dos-ddos-project
docker compose up -d --build      # build images and start all containers
docker compose ps                 # verify: victim, detector, attacker1..3 are Up
```

Open `http://localhost:8080` to confirm the victim web server responds.

## Usage

> Run the attack phases only against the lab's `victim`. See the disclaimer above.

**1. Start the detector** (in its own terminal):

```bash
docker exec -it detector python3 /app/detector.py \
  --pps 40 --syn 25 --victim 172.30.0.10 --csv /app/attack.csv

# Adaptive thresholds (EWMA): learns the baseline; --pps/--syn act as a safety floor
docker exec -it detector python3 /app/detector.py --adaptive --victim 172.30.0.10 --csv /app/attack.csv
```

**2. Launch a single attack** (another terminal):

```bash
# SYN flood (L4), with IP spoofing
docker exec attacker1 python3 /app/syn_flood.py 172.30.0.10 -p 80 --spoof

# HTTP flood (L7), 20 threads for 30 seconds
docker exec attacker1 python3 /app/http_flood.py 172.30.0.10 -p 80 -t 20 -d 30
```

**3. Launch a distributed attack** from all three sources:

```powershell
# PowerShell orchestrator (Windows)
.\run_ddos.ps1 syn        # or: .\run_ddos.ps1 http
```

**4. Run the reproducible scenarios** (baseline + A/B/C, one CSV each):

```bash
python experiments/run_scenarios.py
```

**5. Guided one-command demo** (narrated: normal → DoS → DDoS SYN → DDoS HTTP).
It preflight-checks Docker and the containers, streams the detector live, and writes a plot:

```bash
python experiments/demo.py
```

**6. Analyze the results:**

```bash
python analysis/metrics.py detection/A.csv --truth DoS       # detection time / FP / FN / table
python analysis/plot_attack.py detection/A.csv -o analysis/A.png
```

**7. Tear down the lab:**

```bash
docker compose down
```

## Detection Mechanism

The detector (`detection/detector.py`) snapshots a counter every `--interval` (default 1s) and
decides per window:

- **Inbound-only counting** (`--victim`, default `172.30.0.10`): only packets whose
  `dst == victim` are counted, excluding the victim's own replies (e.g. SYN-ACK). Without this,
  the victim's replies would be counted as a second source and inflate the ACK rate.
- **Trigger**: an alert is raised when `pps ≥ --pps` **or** `syn/s ≥ --syn`.
- **Adaptive thresholds** (`--adaptive`): instead of fixed values, the detector learns the baseline
  with an EWMA and triggers on `pps/syn > μ + k·MAD` (with `--pps/--syn` as a floor), which reduces
  false positives when legitimate traffic drifts. See the theory guide for a comparison.
- **DoS vs DDoS**: decided by the number of distinct source IPs, `n_src` — `1` ⇒ **DoS**,
  `≥ 2` ⇒ **DDoS**.
- **Source entropy** `H(src) = − Σ pᵢ · log₂(pᵢ)` measures how evenly traffic is spread across
  sources (reported alongside `n_src`).
- **SYN flood tag**: added when `syn/s ≥ --syn` **and** `ack/s < syn/s × 0.2` (half-open
  connections produce very few ACKs).

Output columns (also written to CSV with `--csv`):
`time, pps, syn_s, ack_s, h_src, h_dport, n_src, alert`.

## Results

Three reference scenarios, validated in the lab (detection time ≈ 0 s, 0 false positives):

| Scenario                | pps  | syn/s | ack/s | n_src | H(src) | Verdict            |
|-------------------------|------|-------|-------|-------|--------|--------------------|
| A — 1-source SYN        | 58   | 29    | 0     | 1     | 0.00   | DoS `[SYN flood]`  |
| B — 3-source SYN + spoof| 132  | 66    | 0     | 66    | 6.04   | DDoS `[SYN flood]` |
| C — 3-source HTTP (L7)  | 2196 | 607   | 1639  | 3     | 1.58   | DDoS               |

![Demo timeline](assets/demo.png)

The **finalized dataset and figures used in the report** are committed under
[`results/final/`](results/final/) (CSV data, run metadata, and the corresponding plots). All
other run outputs are git-ignored because they are reproducible by re-running the lab.

## Learning material

A full theory guide for the team (in Vietnamese) can be read directly on GitHub:
**[`docs/LyThuyet_DoS_DDoS.md`](docs/LyThuyet_DoS_DDoS.md)**. It covers DoS/DDoS concepts, the attack
and detection mechanisms, adaptive thresholding, and a state-of-the-art comparison. A downloadable
Word version is also included: [`TaiLieu_LyThuyet_DoS_DDoS.docx`](TaiLieu_LyThuyet_DoS_DDoS.docx).

## Machine learning (experimental)

As a step toward flow-based, learning-driven detection (the direction of the CICDDoS2019 line of
research), [`ml/`](ml/) trains classifiers on flow features and compares them against a
single-threshold rule — the baseline analogous to this project's rule-based detector.

```bash
pip install pandas scikit-learn
python ml/make_synthetic.py      # generate a CICDDoS2019-style sample (noisy, overlapping classes)
python ml/train.py               # train RandomForest + HistGradientBoosting, evaluate, plot
python ml/train.py --data path/to/CICDDoS2019.csv   # or point at the real dataset
```

`ml/make_synthetic.py` produces a **synthetic, CICDDoS2019-style** sample (not real data) so the
pipeline runs out of the box with meaningful — not perfect — scores. `ml/train.py` auto-handles the
CICDDoS2019 CSV schema (column stripping, inf/NaN cleanup, id-column removal), so pointing `--data`
at the real CSVs just works.

On the sample, attack-detection F1 rises from **0.86** (single-threshold rule) to **0.99**
(RandomForest / HistGradientBoosting), and the models additionally identify the attack *type*
(SYN / HTTP / UDP) at ~0.98 macro-F1 — something a single threshold cannot do.

![ML vs rule F1](assets/ml_f1_compare.png)

## Project Structure

```
.
├── attacker/Dockerfile          # attacker/detector image (scapy + hping3 + tcpdump)
├── attacks/
│   ├── syn_flood.py             # L4 SYN flood (scapy), optional --spoof
│   └── http_flood.py            # L7 HTTP flood (multi-threaded GET)
├── detection/detector.py        # real-time detector (threshold + entropy + classification)
├── experiments/
│   ├── run_scenarios.py         # reproducible A/B/C runs -> CSV + meta
│   └── demo.py                  # narrated one-command demo with Docker preflight
├── analysis/
│   ├── plot_attack.py           # timeline plots from CSV
│   └── metrics.py               # detection time / FP / FN / classification table
├── results/final/               # finalized dataset + figures used in the report (committed)
├── docker-compose.yml           # isolated lab topology
├── run_ddos.ps1                 # PowerShell orchestrator (3 attackers in parallel)
└── TaiLieu_LyThuyet_DoS_DDoS.docx
```

## Limitations

- A single host spoofing many IPs is **indistinguishable** from many real hosts as seen by the
  victim (both look like "many sources").
- Rate thresholds are sensitive to **flash crowds** (false positives) and miss **low-and-slow**
  attacks such as Slowloris (false negatives).
- Entropy values depend on the **baseline** and the observation window length.
- Detection is **host-based** at the victim; truly volumetric attacks that saturate the uplink
  must be mitigated **upstream** (firewall / rate limiting / CDN / scrubbing).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention (Conventional Commits) and the
edit → changelog → commit → push workflow. Notable changes are tracked in
[CHANGELOG.md](CHANGELOG.md).
