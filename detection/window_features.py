#!/usr/bin/env python3
"""Module dac trung muc-CUA-SO DUNG CHUNG cho detector LIVE va bo trich PCAP offline.

Muc dich (rang buoc 4): cong thuc dac trung o detector live va o bo trich tu pcap phai
GIONG HET -> dat o day MOT noi duy nhat, ca hai ben import ve dung cong thuc.

Giao dien chung = bo dem MOT cua so (giong tuple ma 2 backend scapy/ebpf cua detector tra ve):
  packets, syn, ack, udp, icmp, src_counter, dport_counter, nbytes
-> features_from_counts(...) -> dict dac trung theo ten.

Phan loai goi dung chung qua add_packet() (cung quy tac SYN/ACK/UDP/ICMP + loc inbound
dst==victim nhu detector.on_packet) de bo trich pcap khop tung goi voi detector.

LUU Y tich hop LIVE: detector.py hien tinh dac trung noi tuyen (inline) cho A/B/C va CHUA
dem icmp/bytes. File nay la nguon-chan-ly cho duong OFFLINE (pcap) truoc. Khi wire model moi
vao detector live, doi detector.py sang import va dung ham o day; neu model cuoi dung icmp_s
hoac avg_pkt_size thi phai bo sung dem icmp + bytes vao detector.on_packet/ebpf truoc.
"""
import collections
import math

# ===== Thu tu dac trung CO DINH cho MODEL =====
# train_window.py va (sau nay) detector --ml import tu day -> mot nguon duy nhat.
# Day la tap LIVE-SUPPLYABLE: moi dac trung detector live deu tinh duoc tu bo dem hien co
# (pps/syn_s/ack_s/udp_s; h_src/h_dport/n_src; 3 ty le dan xuat). 9 dac trung chuan cua repo
# + rate_per_src (tach flash-crowd per-src thap vs DDoS per-src cao).
FEATURES = ["pps", "syn_s", "ack_s", "udp_s", "h_src", "h_dport", "n_src",
            "syn_ratio", "ack_syn_ratio", "rate_per_src"]

# ===== Tap TRICH RONG ghi ra windows CSV (de kham pha + prune theo importance) =====
# Gom FEATURES + 3 dac trung chan doan detector live CHUA tinh duoc (icmp_s, udp_ratio,
# avg_pkt_size) -> KHONG nam trong FEATURES mac dinh. Muon dua vao train thi them vao FEATURES,
# NHUNG phai bo sung dem tuong ung o detector live truoc khi deploy model do voi --ml.
EXTRACT = ["pps", "syn_s", "ack_s", "udp_s", "icmp_s", "h_src", "h_dport", "n_src",
           "syn_ratio", "ack_syn_ratio", "udp_ratio", "avg_pkt_size", "rate_per_src"]

# so hieu giao thuc IP
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17


def entropy(counter):
    # Shannon entropy (bit) cua phan bo dem. Rong -> 0. GIONG HET detector.entropy.
    total = sum(counter.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def new_counters():
    # Bo dem rong cho mot cua so (hoac mot bucket).
    return {"packets": 0, "syn": 0, "ack": 0, "udp": 0, "icmp": 0, "nbytes": 0,
            "src": collections.Counter(), "dport": collections.Counter()}


def add_packet(c, src, dst, proto, tcp_flags, dport, iplen, victim=None):
    """Dem MOT goi vao bo dem c. Quy tac GIONG detector.on_packet:
      - loc INBOUND: neu co victim thi chi dem goi dst==victim (bo goi victim tu tra ve).
      - packets/nbytes/src tang cho MOI goi IP (ke ca ICMP).
      - TCP: dem dport + co SYN (0x02) + co ACK (0x10).
      - UDP: chi tang udp (KHONG dem dport -> h_dport chi theo TCP, khop detector hien tai).
      - ICMP: tang icmp (dac trung mo rong).
    iplen = truong do dai tang IP (ip.len) -> kich thuoc that tren day, KHONG phu thuoc snaplen.
    """
    if victim and dst != victim:
        return
    c["packets"] += 1
    c["nbytes"] += iplen
    c["src"][src] += 1
    if proto == PROTO_TCP:
        c["dport"][dport] += 1
        if tcp_flags is not None:
            if tcp_flags & 0x02:
                c["syn"] += 1
            if tcp_flags & 0x10:
                c["ack"] += 1
    elif proto == PROTO_UDP:
        c["udp"] += 1
    elif proto == PROTO_ICMP:
        c["icmp"] += 1


def merge_counters(bucket_list):
    # Gop nhieu bucket thanh mot cua so (dung cho cua so truot goi dau: window = nhieu stride-bucket).
    m = new_counters()
    for c in bucket_list:
        m["packets"] += c["packets"]
        m["syn"] += c["syn"]
        m["ack"] += c["ack"]
        m["udp"] += c["udp"]
        m["icmp"] += c["icmp"]
        m["nbytes"] += c["nbytes"]
        m["src"].update(c["src"])
        m["dport"].update(c["dport"])
    return m


def features_from_counts(packets, syn, ack, udp, icmp, src_counter, dport_counter,
                         nbytes, interval):
    """Tinh dict dac trung tu bo dem mot cua so. interval = do dai cua so (giay).

    Cong thuc PHAI khop detector live cho cac dac trung chung:
      pps/syn_s/ack_s/udp_s/icmp_s = count / interval
      h_src/h_dport = entropy(counter);  n_src = so IP nguon rieng biet
      syn_ratio    = syn_s / max(pps, 1)        (giong detector.py)
      ack_syn_ratio= ack_s / max(syn_s, 1)      (giong detector.py)
      udp_ratio    = udp_s / max(pps, 1)
      avg_pkt_size = nbytes / packets           (nbytes lay theo ip.len -> rang buoc 3)
      rate_per_src = pps / max(n_src, 1)        (per-src: tach flash-crowd vs HTTP-DDoS)
    """
    pps = packets / interval
    syn_s = syn / interval
    ack_s = ack / interval
    udp_s = udp / interval
    icmp_s = icmp / interval
    n_src = len(src_counter)
    return {
        "pps": pps,
        "syn_s": syn_s,
        "ack_s": ack_s,
        "udp_s": udp_s,
        "icmp_s": icmp_s,
        "h_src": entropy(src_counter),
        "h_dport": entropy(dport_counter),
        "n_src": n_src,
        "syn_ratio": syn_s / max(pps, 1.0),
        "ack_syn_ratio": ack_s / max(syn_s, 1.0),
        "udp_ratio": udp_s / max(pps, 1.0),
        "avg_pkt_size": (nbytes / packets) if packets else 0.0,
        "rate_per_src": pps / max(n_src, 1),
    }


def features_from_counters(c, interval):
    # Tien ich: tinh dac trung tu bo dem kieu new_counters().
    return features_from_counts(c["packets"], c["syn"], c["ack"], c["udp"], c["icmp"],
                                c["src"], c["dport"], c["nbytes"], interval)
