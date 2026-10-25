<p align="center">
  <img src="banner.svg" alt="DoS/DDoS Attack Simulation, Detection & Defense Lab — PBL3" width="100%">
</p>

# DoS/DDoS Attack Simulation, Real-Time Detection & Defense Lab

A comprehensive, dual-mode research and educational laboratory that **simulates** DoS/DDoS attacks, **extracts 9 real-time traffic features**, and performs **live classification and in-kernel mitigation**. Built as an end-of-term capstone project (DUT — PBL3).

The system observes inbound network traffic in 1-second sliding windows, computing 9 real-time metrics including **Shannon entropy of source IPs & destination ports**, **distinct source IP counts**, and **protocol ratios**. It accurately differentiates benign traffic from single-source **DoS** and distributed **DDoS**, and identifies attack vectors across **L4 SYN flood**, **L3/L4 UDP flood**, and **L7 HTTP flood**.

The project natively supports two deployment environments:
1. **Physical Multi-Machine Deployment**: Real laptops (1 Victim + 2 Attackers) communicating over a local WiFi/LAN network.
2. **Virtualized Docker Lab**: Fully isolated container topology (`172.30.0.0/24`) with 1 victim, 6 attacker nodes, and 1 detector container.

---

## ⚠️ Disclaimer — Educational & Defensive Research Only

This project is developed **strictly for education and defensive cybersecurity research**. All attack scripts must only ever target your own authorized laboratory victim node (either on the private Docker `172.30.0.0/24` subnet or within an isolated, dedicated testing LAN/WiFi network).

- **Do NOT** target any host, network, server, or device without explicit written permission.
- Launching unauthorized denial-of-service attacks is **illegal** under cybersecurity laws worldwide.
- The authors accept **no liability** for misuse. You are solely responsible for all actions performed with this software.

---

## Table of Contents

- [Overview](#overview)
- [System Architectures](#system-architectures)
  - [1. Physical Multi-Machine Topology (WiFi / LAN)](#1-physical-multi-machine-topology-wifi--lan)
  - [2. Virtualized Docker Lab](#2-virtualized-docker-lab)
- [Attack Vectors (3 Types)](#attack-vectors-3-types)
- [Detection Engine & 9 Real-Time Features](#detection-engine--9-real-time-features)
- [Real-Time Victim Defense Console (Dashboard)](#real-time-victim-defense-console-dashboard)
- [Machine Learning Pipeline](#machine-learning-pipeline)
  - [1. Flow-Level Benchmark on CICDDoS2019](#1-flow-level-benchmark-on-cicddos2019)
  - [2. Live Window-Level Model](#2-live-window-level-model)
- [Closed-Loop In-Kernel Defense (eBPF / XDP)](#closed-loop-in-kernel-defense-ebpf--xdp)
- [Experimental Results](#experimental-results)
- [Installation & Quick Start](#installation--quick-start)
  - [Mode A: Physical Multi-Machine (WiFi / LAN)](#mode-a-physical-multi-machine-wifi--lan)
  - [Mode B: Docker Lab](#mode-b-docker-lab)
- [Project Structure](#project-structure)
- [Limitations & Future Work](#limitations--future-work)
- [Contributing & Development](#contributing--development)

---

## Overview

The system is organized into three cooperating pillars:

1. **Attack Generation**:
   - **L4 TCP SYN Flood** ([`attacks/syn_flood.py`](attacks/syn_flood.py)): Exploits TCP 3-way handshake half-open states; supports random IP spoofing (`--spoof`).
   - **L3/L4 UDP Flood** ([`attacks/udp_flood.py`](attacks/udp_flood.py)): High-rate volumetric datagram flooding targeting random/fixed ports; supports IP spoofing (`--spoof`).
   - **L7 HTTP Flood** ([`attacks/http_flood.py`](attacks/http_flood.py)): Multi-threaded GET requests consuming application worker pools and server CPU.
2. **Real-Time Detection & Feature Extraction**:
   - Computes **9 window-level features** every second (`pps`, `syn_s`, `ack_s`, `udp_s`, `h_src`, `h_dport`, `n_src`, `syn_ratio`, `ack_syn_ratio`).
   - Dual thresholding: **Fixed rules** or **Adaptive EWMA + MAD** baseline learning.
   - Dual packet capture engines: userspace **Scapy** or in-kernel **eBPF/XDP** for line-rate accuracy.
   - Concurrent **Machine Learning classification** (Random Forest window model).
3. **Victim Defense Console**:
   - Standalone, light-themed web monitoring dashboard ([`dashboard/`](dashboard/)) running on the victim node.
   - Displays live attack classification, 9 rolling sparkline charts, top attacker IP distribution with spoof warnings, chronological security event logs, and service health probes.

---

## System Architectures

### 1. Physical Multi-Machine Topology (WiFi / LAN)

Designed for realistic demonstrations and classroom testing using 3 physical Linux laptops connected to a dedicated WiFi router or private switch:

```
                  Dedicated WiFi / LAN (e.g., 192.168.1.0/24 via DHCP)
        ┌─────────────────────────┬─────────────────────────┐
        │                         │                         │
┌───────▼──────────────┐   ┌──────▼───────────────┐  ┌──────▼───────────────┐
│    Victim Laptop     │   │  Attacker 1 Laptop   │  │  Attacker 2 Laptop   │
│                      │   │                      │  │                      │
│ • Nginx Web (Port 80)│   │ • syn_flood.py       │  │ • syn_flood.py       │
│ • detector.py        │   │ • udp_flood.py       │  │ • udp_flood.py       │
│ • Victim Console     │   │ • http_flood.py      │  │ • http_flood.py      │
│   (Port 3000)        │   │ • hping3 / ab        │  │ • hping3 / ab        │
└──────────────────────┘   └──────────────────────┘  └──────────────────────┘
```

- **Victim Laptop**: Hosts the target web server (Nginx), runs `detector.py` sniffing the wireless interface (`--iface wlan0`), and serves the **Victim Defense Console** at `http://localhost:3000`.
- **Attacker 1 & 2 Laptops**: Generate traffic independently or coordinated via SSH using [`run_ddos_remote.sh`](run_ddos_remote.sh). With 2 physical attackers, L7 HTTP flood achieves genuine distributed DDoS (`n_src = 2`) without relying on synthetic IP spoofing.
- See detailed physical setup guide: **[`docs/MULTI_MACHINE.md`](docs/MULTI_MACHINE.md)**.

### 2. Virtualized Docker Lab

For automated experimentation, CI testing, and reproducible scenario benchmarks:

```
                            Isolated Bridge Network: dos-lab (172.30.0.0/24)
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                        │
  │  ┌────────────────────────┐      ┌────────────────────────┐     ┌───────────────────┐  │
  │  │ victim (172.30.0.10)   │      │ detector (netns victim)│     │ attacker1 (.21)   │  │
  │  │ • nginx:alpine         │◄────►│ • eBPF XDP + detector  │◄────┤ • scapy, hping3   │  │
  │  │ • published :8080      │      │ • scikit-learn / joblib│     │ attacker2..6 (.26)│  │
  │  └────────────────────────┘      └────────────────────────┘     └───────────────────┘  │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

| Container | Image / Recipe | IP Address | Primary Role |
|---|---|---|---|
| `victim` | `nginx:alpine` | 172.30.0.10 | Target web server, published to host `8080` |
| `detector` | `./detection` | Shares `victim` netns | In-kernel XDP / userspace sniffer; ML engine |
| `attacker1` | `./attacker` | 172.30.0.21 | Primary attack node (`NET_RAW`, `NET_ADMIN`) |
| `attacker2`–`attacker6` | `./attacker` | 172.30.0.22–26 | Distributed attack sources (6 real sources for L7 DDoS) |

---

## Attack Vectors (3 Types)

| Property | L4 SYN Flood | L3/L4 UDP Flood | L7 HTTP Flood |
|---|---|---|---|
| **Script** | [`attacks/syn_flood.py`](attacks/syn_flood.py) | [`attacks/udp_flood.py`](attacks/udp_flood.py) | [`attacks/http_flood.py`](attacks/http_flood.py) |
| **OSI Layer** | Layer 4 (Transport / TCP) | Layer 3/4 (Transport / UDP) | Layer 7 (Application / HTTP) |
| **Exhaustion Target** | TCP SYN half-open connection backlog | Network bandwidth, socket buffers, CPU | Web server thread/worker pools, CPU |
| **3-Way Handshake** | Incomplete (Sends `SYN`, ignores `SYN-ACK`) | None (Connectionless datagrams) | Complete (Full TCP handshake + GET requests) |
| **IP Spoofing** | Supported (`--spoof`, random `10.x.x.x`) | Supported (`--spoof`, random `10.x.x.x`) | Not possible (Requires real 2-way TCP reply) |
| **Traffic Signature** | High `syn_s`, `ack_s ≈ 0`, high `syn_ratio` | High `udp_s`, `syn_s ≈ 0`, `ack_s ≈ 0` | High `pps`, high `ack_s`, high `ack_syn_ratio` |

---

## Detection Engine & 9 Real-Time Features

The detector ([`detection/detector.py`](detection/detector.py)) operates over a 1-second sliding window (`--interval 1.0`), inspecting all incoming packets. To prevent the victim's own responses (e.g. `SYN-ACK`) from polluting source statistics, it strictly enforces **inbound-only filtering** (`--victim <ip>`).

### The 9 Real-Time Window Features

| # | Feature Key | Unit | Description & Formula | Role in Classification |
|---|---|---|---|---|
| 1 | `pps` | pkts/s | Total inbound packets received per second | Measures volumetric intensity; triggers alerts when exceeding threshold |
| 2 | `syn_s` | pkts/s | TCP packets with `SYN` flag set per second | Primary indicator of TCP SYN connection flooding |
| 3 | `ack_s` | pkts/s | TCP packets with `ACK` flag set per second | Validates complete TCP connections; distinguishes L4 from L7 |
| 4 | `udp_s` | pkts/s | UDP datagrams received per second | Identifies volumetric UDP flooding |
| 5 | `h_src` | bits | Shannon entropy of source IP addresses: $H(src) = -\sum_{i} p_i \log_2(p_i)$ | Measures source dispersion: $H \approx 0$ (single IP), $H \gg 0$ (distributed/spoofed) |
| 6 | `h_dport` | bits | Shannon entropy of destination ports: $H(dport) = -\sum_{j} p_j \log_2(p_j)$ | Detects targeted service attacks ($H \approx 0$) vs port scanning/random floods |
| 7 | `n_src` | count | Number of distinct source IP addresses in window | Decisive metric: $n\_src = 1 \implies \mathbf{DoS}$, $n\_src \ge 2 \implies \mathbf{DDoS}$ |
| 8 | `syn_ratio` | ratio | Ratio of SYN packets to total traffic: $syn\_s / \max(pps, 1.0)$ | Close to $1.0$ during pure SYN floods; low during HTTP or UDP floods |
| 9 | `ack_syn_ratio`| ratio | Ratio of ACK packets to SYN packets: $ack\_s / \max(syn\_s, 1.0)$ | $\gg 1.0$ for completed HTTP sessions; $\approx 0.0$ for half-open SYN floods |

### Classification Logic

1. **Trigger Condition**:
   - Fixed: `pps ≥ --pps` **or** `syn/s ≥ --syn`.
   - Adaptive EWMA: `pps > μ_pps + k·MAD_pps` **or** `syn_s > μ_syn + k·MAD_syn` (with minimum floor). Baseline updates only during benign windows.
2. **Scope Classification**:
   - `n_src == 1` $\implies$ **DoS** (Single source, verified by $H(src) \approx 0.00$).
   - `n_src >= 2` $\implies$ **DDoS** (Distributed sources or random IP spoofing, $H(src) > 0.00$).
3. **Attack Vector Tagging**:
   - **`[SYN flood]`**: `syn/s ≥ threshold` AND `ack/s < syn/s × 0.2` (half-open connection starvation).
   - **`[UDP flood]`**: `udp/s ≥ --pps` AND `udp/s > syn/s` (datagram flooding dominates).
   - **`HTTP flood`**: High `pps` AND high `ack_s` ($ack\_s \gg syn\_s$, $ack\_syn\_ratio \gg 1.0$).

---

## Real-Time Victim Defense Console (Dashboard)

A standalone, high-performance web console ([`dashboard/`](dashboard/)) runs directly on the victim machine, presenting real-time security insights without overhead.

<p align="center">
  <img src="assets/dashboard.png" alt="Victim Defense Console Interface" width="100%">
</p>

### Key Console Capabilities

- **Real-Time Classification Status Banner**: Instantly displays network state (`BENIGN`, `DoS`, or `DDoS`), attack vector badges (`[SYN flood]`, `[UDP flood]`, `[HTTP flood]`), active threshold values, and Machine Learning confidence scores.
- **Service Health Probe**: Pings the local Nginx web service every 3 seconds, rendering response latency (ms) and HTTP status codes to verify target availability under load.
- **9 Rolling Sparkline Canvas Charts**: Dynamic 60-second sliding window graphs for all 9 real-time features (`pps`, `syn_s`, `ack_s`, `udp_s`, `h_src`, `h_dport`, `n_src`, `syn_ratio`, `ack_syn_ratio`) with peak indicators and threshold lines.
- **Top Attacker IPs Table**: Ranks top offending IP addresses with per-second rates, total packet volume, traffic percentage share, and automated **IP Spoofing Warning** tags when random source address generation is detected.
- **Security Event Log**: Chronological audit log with severity indicators (`safe`, `warn`, `crit`, `info`) tracking state transitions, attack start/stop events, and mitigation actions.

### Launching the Console

```bash
cd dashboard
npm install

# Option 1: Auto-spawns detector.py on physical WiFi interface
node server.js --iface wlan0 --victim 192.168.1.50 --port 3000

# Option 2: Receive stream from an existing detector process via standard input pipe
python3 detection/detector.py --iface wlan0 --victim 192.168.1.50 --stream | node server.js --no-spawn

# Option 3: Ingestion via REST API (POST /api/metric)
node server.js --no-spawn
```

Access the interface in any web browser at: `http://localhost:3000`.

---

## Machine Learning Pipeline

The project employs a dual-stage machine learning architecture, clearly separating **flow-level benchmarking** from **real-time window-level classification**.

### 1. Flow-Level Benchmark on CICDDoS2019

To evaluate the limitations of single-threshold rules against modern multi-feature learning, [`ml/train.py`](ml/train.py) trains classifiers on the Canadian Institute for Cybersecurity benchmark dataset (**CICDDoS2019**, cleaned parquet format via Kaggle):

- **Data characteristics**: ~131,000 bidirectional flows, 63 statistical flow features (packet size min/max/mean, IAT, forward/backward header lengths, TCP flags) extracted using CICFlowMeter.
- **Fundamental Distinction**: These features represent individual 5-tuple flows over their full lifetime. Cross-flow aggregate metrics like $H(src)$ or $n\_src$ do not exist in flow-level datasets.
- **Binary Detection Performance**:
  - Single-threshold rule (best single flow rate feature): **F1 = 0.60**
  - **Random Forest**: **F1 = 0.999** (Accuracy 99.9%)
  - **HistGradientBoosting**: **F1 = 0.996**
- **Multi-Class Attack Family Classification**: Random Forest achieves **93.0% accuracy** / **0.735 macro-F1** across 13 attack families (NTP, TFTP, SYN, MSSQL, UDP, DNS, LDAP, NetBIOS, SNMP, Portmap).

### 2. Live Window-Level Model

Because flow-level models require completed flow statistics that cannot be evaluated sub-second on raw packets, [`ml/build_window_dataset.py`](ml/build_window_dataset.py) compiles 1-second window snapshots from laboratory runs into a dedicated window dataset.

- [`ml/train_window.py`](ml/train_window.py) trains a lightweight Random Forest model on the 9 real-time features (`detection/window_model.joblib`).
- Evaluated against near-threshold edge cases:
  - **Scenario D**: Low-rate spoofed SYN flood (~24 pps, below rule threshold). The rule catches **0%**, whereas the ML model detects **100%**.
  - **Scenario E**: Benign HTTP flash crowd above rate threshold. The rule generates false alarms; the ML model correctly identifies it as benign.
- Run live alongside rule detection:
  ```bash
  python3 detection/detector.py --victim 192.168.1.50 --ml detection/window_model.joblib
  ```

---

## Closed-Loop In-Kernel Defense (eBPF / XDP)

For line-rate resilience, the detector includes an eBPF backend ([`detection/ebpf_counter.py`](detection/ebpf_counter.py)) leveraging XDP (eXpress Data Path) inside the Linux kernel:

1. **High-Speed Counting**:
   - Ingress packets are parsed and counted directly in kernel memory using eBPF maps before memory allocation or OS networking stack traversal (`XDP_PASS`).
   - On a 120,000 pps flood test, Scapy captured only **57%** of packets due to userspace context switching, while eBPF captured **95%** at true line-rate.
2. **Automated Closed-Loop Blocking (`--block`)**:
   - **Per-Source Rate Blocking**: Any source IP exceeding `--block-pps` (e.g. 300 pps) is added to the BPF `blocklist` map. Offending packets are dropped at the network driver level (`XDP_DROP`).
   - **Auto-Expiring TTL (`--block-ttl`)**: Entries automatically expire (e.g. after 5 seconds) to prevent permanent lockouts.
   - **Global SYN Token Bucket (`--block-syn-rate`)**: For spoofed SYN floods where per-source blocking is ineffective (random IPs), a global in-kernel token bucket drops excess SYN packets while preserving legitimate bandwidth.

---

## Experimental Results

### Reference Scenario Validation

| Scenario | Vector | Target Rate | n_src | H(src) | Detector Verdict | Detection Time |
|---|---|---|---|---|---|---|
| **A** | 1-Source SYN Flood | ~300 pps | 1 | 0.00 | **DoS `[SYN flood]`** | < 1.0 s |
| **B** | Distributed / Spoofed SYN | ~4000 pps | ~2300 | ~11.1 | **DDoS `[SYN flood]`** | < 1.0 s |
| **C** | Multi-Source HTTP Flood | ~1800 pps | 6 (real) | ~2.58 | **DDoS** | < 1.0 s |
| **D** | Low-Rate Stealth SYN | ~24 pps | ~20 | ~4.2 | **DDoS (ML detected)** | < 1.0 s |
| **E** | Legitimate Flash Crowd | ~350 pps | 1 | 0.00 | **BENIGN (ML verified)** | N/A |

### High-Intensity Line-Rate Stress Test

Using `hping3 --flood` and ApacheBench (`ab -c 500`) against the victim web service:

- Under raw line-rate HTTP attack (693,000 pps across 6 sources), modern Linux kernel SYN cookies and static Nginx served **100% of legitimate client requests (200 OK)** with 0 packet drops at `eth0`, with only a slight p95 latency increase (1 ms $\to$ 11 ms).
- Enabling `--block` dropped attacking sources via XDP inside the kernel, collapsing attack traffic from **433,000 pps down to 28 pps** and restoring p95 response times to 1 ms.

---

## Installation & Quick Start

### Mode A: Physical Multi-Machine (WiFi / LAN)

#### 1. Setup the Victim Laptop
```bash
# Install dependencies
sudo apt update && sudo apt install -y nginx python3-scapy tcpdump nodejs npm
sudo systemctl enable --now nginx

# Clone repository
git clone https://github.com/cityengin/dos-ddos-project.git ~/dos-ddos-project
cd ~/dos-ddos-project

# Launch Victim Defense Console & Detector
cd dashboard
npm install
node server.js --iface wlan0 --victim <VICTIM_IP> --port 3000
```
Open `http://localhost:3000` in a browser.

#### 2. Setup Attacker Laptops
```bash
# On each attacker laptop
sudo apt update && sudo apt install -y python3-scapy hping3 apache2-utils git
git clone https://github.com/cityengin/dos-ddos-project.git ~/dos-ddos-project
cd ~/dos-ddos-project

# Launch test attacks against Victim IP:
# L4 SYN Flood (Single Source DoS)
sudo python3 attacks/syn_flood.py <VICTIM_IP> -p 80 --pps 400

# L4 SYN Flood (Spoofed DDoS)
sudo python3 attacks/syn_flood.py <VICTIM_IP> -p 80 --spoof --pps 400

# L3/L4 UDP Flood (Volumetric)
sudo python3 attacks/udp_flood.py <VICTIM_IP> -p 80 --pps 400

# L7 HTTP Flood (Application Layer)
python3 attacks/http_flood.py <VICTIM_IP> -p 80 -t 20 -d 30
```

#### 3. Coordinated Multi-Attacker Orchestration (SSH)
From the victim or control laptop, fire synchronized attacks across both laptops:
```bash
# Coordinated HTTP DDoS (2 real physical sources -> n_src = 2)
./run_ddos_remote.sh http -t <VICTIM_IP> -d 30 -a user@192.168.1.61 -a user@192.168.1.62
```

---

### Mode B: Docker Lab

#### 1. Start the Environment
```bash
git clone https://github.com/cityengin/dos-ddos-project.git
cd dos-ddos-project

# Build and start all 8 containers
docker compose up -d --build
docker compose ps
```

#### 2. Run the Detector
```bash
# Interactive terminal:
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10

# With Adaptive Thresholds (EWMA):
docker exec -it detector python3 /app/detector.py --adaptive --victim 172.30.0.10

# With eBPF/XDP Line-Rate Engine + Closed-Loop Drop:
docker exec -it detector python3 /app/detector.py --engine ebpf --block --victim 172.30.0.10
```

#### 3. Run Automated Scenarios
```bash
# Execute standard A/B/C benchmark runs
python experiments/run_scenarios.py

# Or run the narrated interactive demo
python experiments/demo.py
```

---

## Project Structure

```
.
├── banner.svg                    # Laboratory topology & 9-feature vector vector graphic
├── docker-compose.yml            # Virtualized lab network & container definitions
├── run_ddos.sh                   # Docker orchestration script (6 parallel attackers)
├── run_ddos_remote.sh            # Multi-machine SSH orchestrator for physical laptops
│
├── attacks/                      # Attack generation tools
│   ├── syn_flood.py              # L4 TCP SYN flood (Scapy, raw socket, optional --spoof)
│   ├── udp_flood.py              # L3/L4 UDP flood (Scapy, volumetric, optional --spoof)
│   └── http_flood.py             # L7 HTTP request flood (multi-threaded GET)
│
├── detection/                    # Real-time traffic analysis & detection engine
│   ├── Dockerfile                # Detector container image (Ubuntu + BCC + scikit-learn)
│   ├── detector.py               # 9-feature real-time detector (rule, adaptive, ML, stream)
│   ├── ebpf_counter.py           # In-kernel XDP counting and closed-loop packet filter
│   └── window_model.joblib       # Serialized Random Forest model for live window inference
│
├── dashboard/                    # Real-time Victim Defense Console (Node.js + WebSockets)
│   ├── package.json              # Dashboard dependencies (Express, WS)
│   ├── server.js                 # Backend server (stdin stream, REST API, health probes)
│   └── public/                   # Frontend assets
│       ├── index.html            # Defense console markup (9 sparklines, status banner, logs)
│       ├── style.css             # Modern light theme CSS styles
│       └── app.js                # WebSocket client & 60s dynamic canvas renderers
│
├── ml/                           # Machine Learning research pipeline
│   ├── train.py                  # CICDDoS2019 dataset training & benchmark comparison
│   ├── make_synthetic.py         # Synthetic flow generator for zero-setup verification
│   ├── build_window_dataset.py   # Extracts 9-feature window datasets from scenario runs
│   └── train_window.py           # Trains the live window Random Forest model
│
├── experiments/                  # Reproducible test execution & validation
│   ├── run_scenarios.py          # Runs scenarios A through E with ground-truth metadata
│   └── demo.py                   # Guided, automated end-to-end demonstration
│
├── analysis/                     # Offline analysis & plotting utilities
│   ├── metrics.py                # Computes detection latency, precision, recall, F1
│   └── plot_attack.py            # Generates timeline graphs from CSV logs
│
├── results/final/                # Finalized CSV datasets and publication figures
└── docs/                         # Theoretical & practical documentation
    ├── LyThuyet_DoS_DDoS.md      # Comprehensive technical theory guide (Vietnamese)
    ├── MULTI_MACHINE.md          # Multi-laptop WiFi deployment guide (Vietnamese)
    └── TESTING.md                # Verification, testing & validation walkthrough
```

---

## Limitations & Future Work

- **IP Spoofing Ambiguity**: An attacker spoofing random source addresses from a single machine produces indistinguishable traffic signatures from thousands of authentic distributed hosts at the victim interface.
- **Low-and-Slow Attack Vectors**: Volumetric thresholds focus on packet intensity and do not detect slow application-layer starvation attacks such as Slowloris or slow-read floods.
- **Local Saturation Limits**: Host-based defenses (including XDP) protect server compute resources but cannot protect against upstream network pipe saturation; multi-gigabit volumetric floods must be filtered upstream via BGP Flowspec or scrubbing centers.
- **Future Directions**: Implement CUSUM change-point algorithms, integrate flow-based P4/eBPF tracking, and evaluate behavioral modeling for application-layer botnet detection.

---

## Contributing & Development

Contributions are welcome! Please follow the established coding standards:
- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `style:`).
- Verify modifications against the end-to-end testing checklist in [`docs/TESTING.md`](docs/TESTING.md).
- Keep changes documented in `CHANGELOG.md`.

---
*Developed for DUT PBL3 — Information Security & Network Defense.*
