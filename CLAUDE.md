# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

University end-of-term project (DUT PBL3): simulate DoS/DDoS attacks **and** detect them inside a fully isolated Docker lab. Everything runs against the lab's own `victim` container — never a real target. Comments and status notes are written in ASCII-only Vietnamese (no diacritics); keep that convention when editing them. Host environment is **Ubuntu native** (Docker, no WSL2 — faster/more stable than the earlier Windows + Docker Desktop setup; `docker` may need `sg docker -c '...'` if the login session hasn't reloaded the `docker` group).

`PROJECT_STATUS.md` is the running log of results, tuned thresholds, and TODOs — read it first and update it when experiments change the numbers or the task list.

## Lab topology (`docker-compose.yml`)

- `victim` — `nginx:alpine` at `172.30.0.10`, published to `localhost:8080`.
- `attacker1..6` — built from `attacker/Dockerfile`, IPs `172.30.0.21..26`. Have `NET_RAW`+`NET_ADMIN` (required for scapy/hping3 raw packets and IP spoofing). Tools: scapy + `hping3` + `ab` (apache2-utils) + tcpdump. Mount `./attacks` at `/app`. (6 containers so an L7/HTTP DDoS shows 6 real sources; SYN floods also spoof for thousands.)
- `detector` — built from its own `detection/Dockerfile` (ubuntu + scapy + `python3-bpfcc` for the eBPF engine + pinned `scikit-learn`/`joblib` for `--ml`), runs `network_mode: service:victim` so it shares the victim's network namespace and observes the victim's `eth0` directly. Mounts `./detection` at `/app`; has `CAP_BPF`/`CAP_PERFMON`/`CAP_NET_ADMIN` and read-only mounts of `/lib/modules`, `/usr/src`, `/sys/kernel/debug` so BCC can compile the XDP program at runtime.
- Network `dos-lab`: bridge, subnet `172.30.0.0/24`.

The attack/detection Python scripts are **bind-mounted**, so edits take effect on the next `docker exec` without rebuilding. Rebuild images only when changing `attacker/Dockerfile` (installed tools) or adding pip deps.

## Common commands

```bash
docker compose up -d --build          # bring up lab (build attacker/detector image)
docker compose down                   # tear down

# Detector (run in its own terminal; sniffs victim eth0)
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 --csv /app/attack.csv

# Single attacker, manual
docker exec attacker1 python3 /app/syn_flood.py 172.30.0.10 -p 80 --spoof
docker exec attacker1 python3 /app/http_flood.py 172.30.0.10 -p 80 -t 20 -d 30

# All 6 attackers in parallel (bash orchestrator)
./run_ddos.sh syn        # or: ./run_ddos.sh http
./run_ddos.sh syn -t 172.30.0.10 -d 30

# Reproducible experiment run + analysis (host Python, needs matplotlib)
python experiments/run_scenarios.py                       # runs A/B/C -> detection/{A,B,C}.csv + .meta.json
python experiments/run_scenarios.py --only B --intensity max   # MAX intensity (hping3/ab line-rate; A/B/C only; forces eBPF)
./run_ddos.sh syn -i max        # 6-source line-rate flood (bash orchestrator: hping3 --flood; `http -i max` -> ab -k -c 500)
python analysis/metrics.py detection/A.csv --truth DoS    # detection time / FP / FN / classification table
python analysis/plot_attack.py detection/A.csv -o analysis/A.png
```

There is no build step, test suite, or linter — this is a set of standalone scripts driven by Docker, the orchestrator, and `experiments/run_scenarios.py`. The analysis scripts (`analysis/`) run on the **host** and need matplotlib; everything else runs inside containers.

## Detection logic (`detection/detector.py`)

The whole point of the project lives here. The main loop snapshots and resets a per-window counter every `--interval` (default 1s) and decides the verdict. The counter has a pluggable **backend** (`--engine`):

- **Counting engine** (`--engine scapy|ebpf`, default `scapy`): `scapy` runs `sniff` in a background thread (simple, but drops packets at high pps). `ebpf` (`detection/ebpf_counter.py`, BCC) attaches an **XDP ingress** program to `eth0` in the victim's netns that counts into BPF maps (packets/syn/ack + `src_ip` + `dport` hashes) and always returns `XDP_PASS` — **detect-only, never drops**. Both backends return the same `(packets, syn, ack, src_counter, dport_counter)` per window, so the rule, `--adaptive`, `--ml`, `--stream`, `--csv` are all unchanged. In the lab, on a 120k-packet high-rate flood scapy observed only **57%** while XDP observed **95%** (and saw the true ~30k pps peak that scapy, capped near 7k pps, never sees). The `src_ip` BPF hash is **capped at 8192 entries** so a `--rand-source` SYN flood (tens of thousands of distinct IPs/s) can't stall the per-window userspace readback; the packet/syn/ack PERCPU counters stay exact, only `n_src` saturates (~8192 = still unambiguously "many sources" → DDoS, `H(src)`≈13).
- **Closed-loop blocking** (`--block`, default off, requires `--engine ebpf`): the eBPF program **counts first, then drops**, so the detector still sees the true attack intensity. Each window, sources whose rate exceeds `--block-pps` (e.g. 200) are added to a `blocklist` BPF map with a TTL (`--block-ttl`, e.g. 5s, auto-expiring — never a permanent block); matching packets return `XDP_DROP` and increment a `blocked` counter. `--block-syn-rate N` adds a global SYN token-bucket (`bpf_spin_lock`) that drops SYNs above `N`/s — the only thing that bites a spoofed SYN flood, since per-source blocking is useless when every packet has a fresh IP (a documented limit). Reports `blocked_src`/`blocked_pps` in the table / `--stream` / `--csv`. Lab demo: a stateful HTTP flood (C) collapses from ~136k to ~242 pps once its 6 sources are blocked; a spoofed SYN flood (B) is unaffected by per-source blocking but `--block-syn-rate 2000` drops ~85% of it (trade-off: some legitimate SYNs dropped). `SIGKILL` can't run the cleanup, so a leaked XDP program is removed by the next detector start (`EbpfCounter.__init__`).
- **Inbound-only counting** (`--victim`, default `172.30.0.10`): because the detector shares the victim's netns it sees *both* directions on eth0. It counts only packets whose `dst == victim`, excluding the victim's own replies. This is critical — without it, the victim's SYN-ACK replies (`src = victim`) get counted as a second source, so a single-source DoS is misclassified as DDoS and `ack_s` is inflated enough to suppress the SYN-flood tag. Set `--victim ""` to count both directions (old buggy behavior; kept for the before/after comparison in `PROJECT_STATUS.md`).
- **Trigger**: `pps >= --pps` OR `syn_s >= --syn`. Note the CLI *defaults* (200/100) are placeholders — the values actually used in the lab are `--pps 40 --syn 25` (see `PROJECT_STATUS.md`). Adjust via flags, not by editing defaults.
- **DoS vs DDoS**: decided by source count **plus dominance**. DDoS when `n_src >= --ddos-min-src` (default 10 — many sources, spoof or many hosts) **or** (`n_src >= 2` **and** the top source's packet share `top_share < --ddos-dom-share`, default 0.8 — no single source dominates); otherwise DoS. The dominance test matters on a **real shared network** (not the isolated Docker lab): a single-source DoS still picks up 1–2 stray background packets from other hosts to the victim each window, so a naive `n_src >= 2` rule misclassifies it as DDoS — `top_share ≈ 1.0` (and `H(src) ≈ 0`) reveals it is really one source (lab-measured on campus WiFi: A non-spoof showed `n=3, H(src)=0.03, top≈0.998`). `H(src)` (Shannon entropy of source IPs) is reported as a dispersion measure but is not the classifier.
- **SYN flood tag**: added when `syn_s >= --syn` and `ack_s < syn_s * 0.2` (half-open connections, few ACKs coming back).
- `--csv` appends `time,pps,syn_s,ack_s,h_src,h_dport,n_src,alert` per window for later plotting.

Known limits to preserve in any writeup (documented in `PROJECT_STATUS.md`): one host spoofing many IPs is indistinguishable from many real hosts at the victim; thresholds are sensitive to flash crowds (false positives) and miss low-and-slow attacks like Slowloris; entropy depends on baseline and window length.

## Attack scripts (`attacks/`)

- `syn_flood.py` — L4, scapy. Crafts `IP()/TCP(flags="S")`; `--spoof` randomizes source IP (`10.x.x.x`) to emulate a multi-source DDoS. Reuses one `conf.L3socket()` (far faster than per-packet `send()`); `--pps N` paces the send rate (controls load, and a higher rate yields more distinct spoofed IPs per window — scenario B reaches `n_src ~2300`). `-c 0` means unbounded (stop with the `timeout` wrapper the orchestrator applies, or Ctrl-C).
- `http_flood.py` — L7, `urllib` across `-t` threads for `-d` seconds; counts successful GETs. Produces ACK-heavy traffic (distinguishes L7 floods from SYN floods in the detector output).
- **Intensity `paced|max`** (run_scenarios `--intensity`, run_ddos.sh `-i`, dashboard "Max intensity" toggle). `paced` (default) uses the two scapy/urllib scripts above *with* rate limiting — keep this for the ML dataset, it's unchanged. `max` swaps them for line-rate tools — `hping3 -S --flood` (SYN; `--rand-source` to spoof) and `ab -k -c 500` (L7) — for **A/B/C only**, and forces `--engine ebpf` (scapy can't count at line-rate). These are external tools in the attacker image, driven by the orchestrators, not scripts in `attacks/`. **Safety**: a flood is huge — isolated lab only, ramp with `--max-rate`/`-r` (hping3 `-i uN`) before `--flood`, keep `pkill hping3`/`ab` ready. Lab finding (detect-only): modern defaults (SYN cookies + static nginx) absorb all three — **0 eth0 rx drops at ~690k pps, legit client stays 100% 200-OK**, only C-max's p95 latency rises ~1→11ms. `--block` then drops A-max ~100% and collapses C-max (~433k→~28 pps). See `PROJECT_STATUS.md`.
