#!/usr/bin/env python3
"""Sinh bo du lieu MAU kieu-CICDDoS2019 (dac trung flow) de kiem chung pipeline ML.

LUU Y: day KHONG phai du lieu that. No mo phong cac dac trung flow giong CICDDoS2019
(flow packets/s, co SYN/ACK, so goi fwd/bwd...) voi NHIEU va CHONG LAP giua BENIGN
(flash-crowd) va tan cong, de so sanh ML vs luat nguong co y nghia (F1 < 1.0).
Khi tai duoc CICDDoS2019 that -> chay train.py voi --data <csv that>.

Chay: python ml/make_synthetic.py
"""
import os
import numpy as np
import pandas as pd

COLS = ["flow_pkts_s", "flow_duration", "syn_flag_cnt", "ack_flag_cnt",
        "fwd_pkts", "bwd_pkts", "pkt_len_mean", "down_up_ratio"]


def block(rng, n, rate, syn, ack, fwd, bwd, plen, dur, label):
    bwd = np.clip(bwd, 0, None)
    return pd.DataFrame({
        "flow_pkts_s": np.clip(rate, 0, None),
        "flow_duration": np.clip(dur, 1, None),
        "syn_flag_cnt": np.clip(syn, 0, None).astype(int),
        "ack_flag_cnt": np.clip(ack, 0, None).astype(int),
        "fwd_pkts": np.clip(fwd, 0, None).astype(int),
        "bwd_pkts": bwd.astype(int),
        "pkt_len_mean": np.clip(plen, 20, 1500),
        "down_up_ratio": bwd / (fwd + 1),
        "Label": label,
    })


def main():
    rng = np.random.default_rng(7)
    parts = []

    # BENIGN: phan lon rate thap, co duoi FLASH-CROWD cao (chong lap voi HTTP flood)
    n = 6000
    rate = np.concatenate([rng.lognormal(3.6, 0.7, int(n * 0.85)),
                           rng.lognormal(6.1, 0.6, n - int(n * 0.85))])
    fwd = rate * rng.uniform(0.3, 0.6, n) + 1
    parts.append(block(rng, n, rate,
                       syn=rng.poisson(2, n),
                       ack=rate * rng.uniform(0.4, 0.9, n),
                       fwd=fwd, bwd=fwd * rng.uniform(0.6, 1.6, n),
                       plen=rng.normal(550, 150, n),
                       dur=rng.uniform(100, 6000, n), label="BENIGN"))

    # SYN_FLOOD: rate cao, SYN rat cao, ACK ~0, bwd ~0, goi nho
    n = 2500
    rate = rng.lognormal(6.5, 0.5, n)
    parts.append(block(rng, n, rate,
                       syn=rate * rng.uniform(0.8, 1.0, n),
                       ack=rng.poisson(1, n),
                       fwd=rate * rng.uniform(0.85, 1.0, n),
                       bwd=rng.poisson(1, n),
                       plen=rng.normal(48, 8, n),
                       dur=rng.uniform(10, 200, n), label="SYN_FLOOD"))

    # HTTP_FLOOD (L7): rate cao (CHONG LAP benign flash-crowd), ACK cao, fwd & bwd deu cao
    n = 2500
    rate = rng.lognormal(6.0, 0.7, n)
    fwd = rate * rng.uniform(0.4, 0.6, n) + 1
    parts.append(block(rng, n, rate,
                       syn=rate * rng.uniform(0.05, 0.15, n),
                       ack=rate * rng.uniform(0.7, 1.0, n),
                       fwd=fwd, bwd=fwd * rng.uniform(0.6, 1.3, n),
                       plen=rng.normal(500, 180, n),
                       dur=rng.uniform(500, 8000, n), label="HTTP_FLOOD"))

    # UDP_FLOOD: rate rat cao, khong SYN/ACK, mot chieu
    n = 2000
    rate = rng.lognormal(6.9, 0.5, n)
    parts.append(block(rng, n, rate,
                       syn=np.zeros(n), ack=np.zeros(n),
                       fwd=rate * rng.uniform(0.9, 1.0, n),
                       bwd=rng.poisson(1, n),
                       plen=rng.normal(700, 300, n),
                       dur=rng.uniform(10, 300, n), label="UDP_FLOOD"))

    df = pd.concat(parts, ignore_index=True)
    # them ~2% nhieu nhan (mo phong du lieu that khong hoan hao) -> F1 < 1.0
    flip = rng.random(len(df)) < 0.02
    labels = df["Label"].unique()
    df.loc[flip, "Label"] = rng.choice(labels, flip.sum())
    df = df.sample(frac=1, random_state=7).reset_index(drop=True)  # tron

    os.makedirs("ml/data", exist_ok=True)
    out = "ml/data/cicddos_style_sample.csv"
    df.to_csv(out, index=False)
    print("[*] Da sinh", len(df), "dong ->", out)
    print(df["Label"].value_counts().to_string())


if __name__ == "__main__":
    main()
