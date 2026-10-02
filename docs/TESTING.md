# Testing & Verification Guide

How to verify each part of the project works correctly, with the expected result for every case.
All tests run against the lab's own `victim` only.

## 0. Prerequisites

```bash
docker compose up -d --build
docker compose ps          # expect: victim, detector, attacker1, attacker2, attacker3 all "Up"
pip install matplotlib pandas scikit-learn   # host, for analysis + ML
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

| Scenario | pps | syn/s | ack/s | n_src | H(src) | Verdict |
|---|---|---|---|---|---|---|
| A — 1-source SYN | ~58 | ~29 | 0 | 1 | 0.00 | `DoS [SYN flood]` |
| B — 3-source SYN + spoof | ~132 | ~66 | 0 | ~66 | ~6.0 | `DDoS [SYN flood]` |
| C — 3-source HTTP (L7) | ~2000+ | ~600 | ~1600 | 3 | ~1.58 | `DDoS` (no SYN tag) |

Key checks: **A is DoS (n_src=1), B/C are DDoS**; SYN floods have `ack≈0`, the HTTP flood has
`ack >> syn`.

**Manual alternative** (two terminals): run the detector (as in step 1, add `--csv /app/attack.csv`)
and in another terminal launch one attack, e.g.
`docker exec attacker1 python3 /app/syn_flood.py 172.30.0.10 -p 80 --spoof`.

---

## 3. Adaptive threshold

```bash
docker exec -it detector python3 /app/detector.py --adaptive --victim 172.30.0.10
# in another terminal, launch any attack (e.g. run_ddos.ps1 syn)
python experiments/adaptive_eval.py      # synthetic comparison -> assets/adaptive_eval.png
```

**Expected:** live mode warms up (~8 s, no alert) then detects the attack. `adaptive_eval.py`
prints: fixed-low threshold = detects but many false positives; fixed-high = misses the attack;
**adaptive = detects AND ~0 false positives**.

---

## 4. Mitigation (L7 defense)

```bash
python mitigation/demo_mitigation.py
```

**Expected:** served attack requests drop from tens of thousands to ~a few hundred
(**~99% blocked**), while the legitimate client stays at 100% success (its latency even drops).
Figure: `assets/mitigation_demo.png`.

---

## 5. Machine learning

```bash
python ml/make_synthetic.py
python ml/train.py
```

**Expected:** attack-detection F1 rises from **~0.86** (single-threshold rule) to **~0.99**
(RandomForest / HistGradientBoosting); multi-class macro-F1 ~0.98. Figures in `assets/ml_*.png`.
(To use the real dataset: `python ml/train.py --data <CICDDoS2019 csv or folder>`.)

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
| Click **B** (DDoS SYN+spoof) | Verdict `DDoS [SYN flood]`, n_src high, H(src) ~6, all 3 links active, victim red "overloaded" |
| Click **C** (DDoS HTTP) | Verdict `DDoS`, ack/s >> syn/s, 3 links active |
| **Stop attack** | Returns to SAFE / idle within ~2 s |
| **L7 rate-limit** toggle ON | Victim shows a shield; on an HTTP flood the attack is throttled |

Security check: the server listens on `127.0.0.1:3000` only (run `netstat` / `Get-NetTCPConnection
-LocalPort 3000` — the local address must be 127.0.0.1, never 0.0.0.0).

---

## 7. Quick full-system checklist

- [ ] 5 containers Up; `http://localhost:8080` serves the nginx page.
- [ ] Baseline: 0 alerts, 0 false positives.
- [ ] A -> DoS, B -> DDoS, C -> DDoS (classification 3/3).
- [ ] SYN floods: `ack≈0`; HTTP flood: `ack >> syn`.
- [ ] Adaptive mode detects and avoids false positives on drifting load.
- [ ] Mitigation blocks ~99% of an HTTP flood; legit client unaffected.
- [ ] ML beats the single-threshold rule (F1 ~0.86 -> ~0.99).
- [ ] Dashboard reflects every scenario live and binds to 127.0.0.1 only.
