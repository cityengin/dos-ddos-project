# Testing & Verification Guide

How to verify each part of the project works correctly, with the expected result for every case.
All tests run against the lab's own `victim` only.

## 0. Prerequisites

```bash
docker compose up -d --build
docker compose ps          # expect: victim, detector, attacker1..6 all "Up"
pip install matplotlib pandas scikit-learn joblib   # host, for analysis + ML
```

Open `http://localhost:8080` -> the nginx welcome page should load (victim is alive).

---

## 1. Baseline (no attack) — thresholds are safe

Run the detector for ~15 s with no attack:

```bash
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10
```

**Expected:** every row shows `pps=0 syn=0 ack=0`, the ALERT column stays empty (no false
positives). Stop with Ctrl-C.

---

## 2. Detection scenarios A / B / C (core result)

The one-shot way (recommended) — runs baseline + all three and writes CSV + metadata:

```bash
python experiments/run_scenarios.py
python analysis/metrics.py detection/A.csv --truth DoS
python analysis/metrics.py detection/B.csv --truth DDoS
python analysis/metrics.py detection/C.csv --truth DDoS
```

**Expected (classification 1/1 for each, detection time 0 s, FP 0):**

| Scenario | pps | syn/s | ack/s | n_src | H(src) | Truth | Verdict (rule) |
|---|---|---|---|---|---|---|---|
| A — 1-source SYN | ~300 | ~150 | 0 | 1 | 0.00 | DoS | `DoS [SYN flood]` |
| B — 6-source SYN + spoof | ~4000 | ~2000 | 0 | **~2300** | ~11.1 | DDoS | `DDoS [SYN flood]` |
| C — 6-source HTTP (L7) | ~1800 | ~400 | ~1400 | 6 | ~2.58 | DDoS | `DDoS` (no SYN tag) |

Key checks: **A is DoS (n_src=1), B/C are DDoS**; SYN floods have `ack≈0`, the HTTP flood has
`ack >> syn`. B uses 6 attackers each spoofing random IPs at a paced rate, so a single window shows
**thousands of distinct source IPs** (`H(src)≈11`); C uses the 6 real containers, so `n_src=6`.

**Near-threshold scenarios D / E** (run with `--only D` / `--only E`) — built to show where the
fixed rule fails and ML does better:

| Scenario | pps | syn/s | ack/s | n_src | Truth | Rule verdict |
|---|---|---|---|---|---|---|
| D — 2-source SYN spoof, low-rate | ~24 | ~24 | 0 | ~24 | DDoS | **none** — below 40/25, so the rule **misses** a real attack |
| E — 1-source HTTP, high-rate (benign flash-crowd) | ~3000 | ~800 | ~2200 | 1 | BENIGN | **DoS** — over threshold, so the rule **false-alarms** |

**Expected:** the rule misses D (false negative) and false-alarms on E (false positive); the ML
detector (section 5) classifies D as `DDoS` and E as `BENIGN`.

**Manual alternative** (two terminals): run the detector (as in step 1, add `--csv /app/attack.csv`)
and in another terminal launch one attack, e.g.
`docker exec attacker1 python3 /app/syn_flood.py 172.30.0.10 -p 80 --spoof`.

---

## 3. Adaptive threshold

```bash
docker exec -it detector python3 /app/detector.py --adaptive --victim 172.30.0.10
# in another terminal, launch any attack (e.g. ./run_ddos.sh syn)
python experiments/adaptive_eval.py      # synthetic comparison -> assets/adaptive_eval.png
```

**Expected:** live mode warms up (~8 s, no alert) then detects the attack. `adaptive_eval.py`
prints: fixed-low threshold = detects but many false positives; fixed-high = misses the attack;
**adaptive = detects AND ~0 false positives**.

---

## 4. Machine learning

Real dataset (recommended):

```bash
pip install kagglehub pyarrow                 # Kaggle API token in env KAGGLE_API_TOKEN or ~/.kaggle
python -c "import kagglehub; print(kagglehub.dataset_download('dhoogla/cicddos2019'))"
python ml/train.py --data <printed-path>      # a folder of per-attack .parquet files
```

Zero-setup fallback (no download):

```bash
python ml/make_synthetic.py
python ml/train.py
```

**Expected (real CICDDoS2019, ~131k flows / 63 features / 13 families):** attack-detection F1
**~0.60** (single-threshold rule) → **0.999** (RandomForest) / **0.996** (HistGradientBoosting);
multi-class accuracy **~0.93**, macro-F1 **~0.74** (volumetric NTP/TFTP/Syn/MSSQL/UDP ≥0.92 F1;
UDP-reflection DNS/LDAP/SNMP/Portmap/NetBIOS overlap and stay low — a documented limit). Figures in
`assets/ml_*.png`, full report in `ml/results/metrics.txt`. Add `--raw-labels` to reproduce the
un-merged 18-label result (macro-F1 ~0.54 — the drop is the dataset's dual `DrDoS_X`/`X` labeling,
not the model).

---

## 5. Window-level ML, live on the detector (`--ml`)

Build the dataset and train the model (host), then run the detector with `--ml` so it classifies
each 1-second window with the model **in parallel with the rule**:

```bash
python ml/build_window_dataset.py        # runs A..E a few times -> ml/data/windows.csv
python ml/train_window.py                # -> detection/window_model.joblib (prints F1)
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 \
    --victim 172.30.0.10 --ml /app/window_model.joblib
# then attack from another terminal, e.g.: python experiments/run_scenarios.py --only D
```

**Expected (`train_window.py`, 316-window lab dataset):** attack-detection F1 **~0.58 (rule) vs
~0.99 (RF)**; multiclass macro-F1 **~0.59 vs ~0.99**; on attack windows below the rule threshold the
rule catches **0%** while the RF catches **100%**; leave-one-run-out F1 **~0.52 (rule) vs ~0.99 (RF)**.

**Expected (detector `--ml` live):** each row shows both the rule ALERT and `ML:<verdict>(<conf>)`.
Baseline -> `BENIGN`, A -> `DoS`, B/C -> `DDoS`, D -> `DDoS` (the rule stays silent), E -> `BENIGN`
(the rule fires). The model loads inside the container because `scikit-learn==1.9.1` + `joblib` are
installed in `attacker/Dockerfile` (rebuild with `docker compose up -d --build` after changing it).

---

## 6. Dashboard (end-to-end, visual)

```bash
cd dashboard && npm install && npm start      # http://127.0.0.1:3000
```

Open the page, then verify each case:

| Action | Expected |
|---|---|
| Idle (no attack) | Verdict **SAFE**, victim node green "idle", pps/syn tiles 0 |
| Click **A** (DoS SYN) | Verdict `DoS [SYN flood]`, victim amber/red, link from attacker1 animates |
| Click **B** (DDoS SYN+spoof) | Verdict `DDoS [SYN flood]`, n_src in the thousands, H(src) ~11, all 6 links active, victim red "overloaded" |
| Click **C** (DDoS HTTP) | Verdict `DDoS`, ack/s >> syn/s, n_src=6, 6 links active |
| **Stop attack** | Returns to SAFE / idle within ~2 s |

The verdict box shows **two lines**: `rule: <X>` (threshold rule) and `ML: <Y> · <conf>%` (window
model, colored by its own verdict), so a rule-vs-ML disagreement is visible. The dashboard starts the
detector with `--ml` automatically when `detection/window_model.joblib` exists (otherwise ML reads
`off`). The **Service health** probe (status + latency) lives in the Network panel.

Security check: the server listens on `127.0.0.1:3000` only (run `netstat` / `Get-NetTCPConnection
-LocalPort 3000` — the local address must be 127.0.0.1, never 0.0.0.0).

---

## 7. Counting engine: scapy vs eBPF (line-rate accuracy)

The detector counts via `--engine scapy` (default) or `--engine ebpf` (XDP, detect-only). To show eBPF
does not drop at high pps, send a fixed number of packets and compare the total each engine observed:

```bash
# per engine: start the detector with --csv, send exactly 120000 spoofed SYNs from 6 sources,
# wait for the flood to finish, stop the detector, then sum the pps column of the CSV.
docker exec -d detector python3 -u /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --csv /app/bnd.csv
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a python3 /app/syn_flood.py 172.30.0.10 -p 80 --spoof -c 20000; done
# ... wait ~20s, then: docker exec detector pkill -f detector.py
awk -F, 'NR>1{s+=$2} END{print s}' detection/bnd.csv      # total packets observed
```

**Expected:** of 120,000 packets sent, `--engine scapy` observes only **~57%** (peak ~6.9k pps, its own
processing ceiling) while `--engine ebpf` observes **~95%** and captures the true peak (~30k pps). At low
rate both are exact (a 5,000-packet test: eBPF 4,986). This is the quantitative evidence that scapy drops
at line-rate and XDP does not. (`--engine ebpf` needs the detector image's `python3-bpfcc` plus the
`CAP_BPF`/mounts in `docker-compose.yml`.)

---

## 8. Closed-loop blocking (XDP drop, `--block`)

Detect-only by default; `--block` (needs `--engine ebpf`) turns the detector into an IPS that drops
flagged sources at XDP. It counts first, then drops, so the detector still reports the true intensity.

```bash
# per-source blocking (works on real-source floods A / C):
docker exec -d detector python3 -u /app/detector.py --iface eth0 --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --block --block-pps 200 --block-ttl 5 --csv /app/blk.csv
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a python3 /app/http_flood.py 172.30.0.10 -p 80 -t 20 -d 16; done
# watch detection/blk.csv: blocked_src rises to 6, pps-to-victim collapses. Stop: pkill detector + floods.

# spoofed SYN (B) needs the global SYN rate limiter instead (per-source is useless): add --block-syn-rate 2000
```

**Expected:**
- C (6-source HTTP, stateful): with `--block`, the 6 sources are blocked (`blocked_src`=6) and the
  attack rate collapses (**~136k → ~242 pps** — dropping SYNs stalls the attacker's TCP handshakes); a
  low-rate legit client stays 200 OK.
- B (spoofed SYN): per-source blocking does nothing (`blocked_src`≈0 — every packet is a fresh IP);
  `--block-syn-rate 2000` drops **~85%** of the flood (trade-off: some legitimate SYNs dropped too).

Safety: blocklist entries carry a TTL (auto-expire — no permanent block); a low-rate client / health
probe (≪ `--block-pps`) is never blocked; `--block` is off by default.

---

## 9. Max intensity (line-rate) & real impact

Two attack intensities, selectable without touching the paced default (needed for the ML dataset):
`paced` (scapy/`http_flood.py`, rate-limited) and `max` (**line-rate** via `hping3`/`ab`, A/B/C only,
requires `--engine ebpf`). **Isolated lab only** — keep `pkill hping3`/`pkill ab` ready.

```bash
# run_scenarios: max mode (uses hping3/ab + eBPF engine). --max-rate caps hping3 (-i uN) for a safe ramp.
python experiments/run_scenarios.py --only A --intensity max --duration 10        # A: 1-source hping3 --flood
python experiments/run_scenarios.py --only B --intensity max                      # B: 6-source --rand-source --flood
python experiments/run_scenarios.py --only A --intensity max --max-rate 200        # ramp: ~5k pps/src, not --flood

# run_ddos.sh: -i max (6 sources)
./run_ddos.sh syn  -i max            # hping3 --rand-source --flood
./run_ddos.sh http -i max            # ab -k -c 500
./run_ddos.sh syn  -i max -r 50000   # capped ~50k pps/src (ramp)

# Dashboard: click "Max intensity: OFF" -> ON, then run A/B/C. Detector already runs eBPF, so no restart.
```

**Measure impact** (detect-only, no `--block`): run a low-rate legit client from the host against the
published victim while an attack runs, and read the victim's `eth0` rx counters for the true rate:

```bash
# true inbound pps (counts all packets reaching the victim, independent of the detector):
docker exec detector sh -c 'cat /proc/net/dev' | awk '/eth0:/{gsub(/:/," ");print "rx_packets="$3}'   # before & after, /seconds
# legit client latency+success:
while :; do curl -s -m3 -o /dev/null -w '%{http_code} %{time_total}\n' http://localhost:8080/; sleep .25; done
```

**Expected (modern-defaults conclusion — report honestly):** A-max ~190k pps, B-max ~123k pps, C-max
~693k pps, **0 rx drops** at the interface, and a legit client stays **100% 200-OK**; the only visible
impact is C-max's p95 latency tail rising ~1ms → ~11ms. SYN cookies + fast static nginx absorb the
floods — downing this victim needs a weaker target or far larger scale. With `--block` on, A-max is
dropped ~100% at XDP and C-max collapses (~433k → ~28 pps) with the latency tail back to ~1ms.

---

## 10. Quick full-system checklist

- [ ] 8 containers Up; `http://localhost:8080` serves the nginx page.
- [ ] Baseline: 0 alerts, 0 false positives.
- [ ] A -> DoS, B -> DDoS, C -> DDoS (classification 3/3).
- [ ] SYN floods: `ack≈0`; HTTP flood: `ack >> syn`.
- [ ] Adaptive mode detects and avoids false positives on drifting load.
- [ ] CICDDoS2019 ML beats the single-threshold rule (F1 ~0.60 -> ~0.999).
- [ ] Window ML: the rule misses D and false-alarms on E; the RF gets both right (F1 ~0.58 -> ~0.99).
- [ ] Detector `--ml` prints both rule and ML verdicts; dashboard shows both lines.
- [ ] `--engine ebpf` observes ~95% of a 120k high-rate flood vs scapy ~57% (detect-only, no drop).
- [ ] `--block` collapses a real-source flood (C: ~136k → ~242 pps); `--block-syn-rate` cuts a spoofed SYN flood (~85%).
- [ ] `--intensity max` (hping3/ab line-rate) reaches ~190k–693k pps; victim absorbs it (0 rx drops, legit client 100% OK).
- [ ] Dashboard reflects every scenario live, has a Max-intensity toggle, and binds to 127.0.0.1 only.
