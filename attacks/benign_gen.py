#!/usr/bin/env python3
"""Sinh luu luong NGUOI DUNG HOP LE (benign) toi nginx victim. Chi dung trong lab co lap.

Khac http_flood.py (tan cong): co NGHI ngau nhien giua cac request (think-time), toc do THAP,
duong dan GET ngau nhien -> giong nguoi dung that. Tao traffic ack >> syn, pps > 0, H(src) nho.

Dung de:
  - sinh lop BENIGN cho dataset (pps>0, khong con dua vao pps==0 de gan nhan).
  - lam NEN giao thoa suot session (benign chay song song attack).
  - flash crowd = chay NHIEU container benign_gen, moi cai toc do THAP -> nhieu nguon that,
    toc-do-moi-nguon THAP (phan biet voi HTTP-DDoS: nhieu nguon per-src CAO).

Vi du (trong container attacker, /app da bind-mount thu muc attacks):
  python3 /app/benign_gen.py 172.30.0.10 --pps 5          # nen nhe ~5 req/s
  python3 /app/benign_gen.py 172.30.0.10 --pps 20 -d 30   # mot thanh vien flash-crowd
"""
import argparse
import random
import time
import urllib.request

# Cac duong dan GET "giong nguoi dung": nginx:alpine tra 200 (trang mac dinh) hoac 404
# (duong dan la) -> deu la request TCP that (ack>>syn), hop le cho muc dich sinh benign.
PATHS = ["/", "/index.html", "/50x.html", "/?q=%d", "/search?p=%d", "/img/%d.png", "/css/main.css"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("--pps", type=float, default=10.0,
                    help="so request/giay MUC TIEU (nhip ~1/pps, co jitter ngau nhien)")
    ap.add_argument("-d", "--duration", type=float, default=0,
                    help="thoi luong (giay); 0 = vo han (dung bang timeout/Ctrl-C)")
    ap.add_argument("--jitter", type=float, default=0.5,
                    help="bien do ngau nhien quanh nhip (0.5 = +/-50%%) de giong nguoi that")
    args = ap.parse_args()

    base = "http://%s:%d" % (args.target, args.port)
    gap = 1.0 / args.pps if args.pps > 0 else 0.1   # nhip trung binh giua 2 request
    t0 = time.time()
    sent = 0
    print("[*] benign_gen -> %s (pps muc tieu=%.1f, jitter=%.0f%%, duration=%s)" % (
        base, args.pps, args.jitter * 100, args.duration or "vo han"))
    while args.duration == 0 or (time.time() - t0) < args.duration:
        path = random.choice(PATHS)
        if "%d" in path:
            path = path % random.randint(1, 999)
        try:
            with urllib.request.urlopen(base + path, timeout=3) as r:
                r.read(512)   # doc it de hoan tat request that (van la traffic hop le)
        except Exception:
            pass              # 404/timeout/reset deu la traffic that, bo qua loi
        sent += 1
        # nghi ngau nhien quanh nhip 1/pps -> think-time giong nguoi dung
        time.sleep(gap * random.uniform(1.0 - args.jitter, 1.0 + args.jitter))
    print("[*] benign_gen xong: %d request trong %.1fs" % (sent, time.time() - t0))


if __name__ == "__main__":
    main()
