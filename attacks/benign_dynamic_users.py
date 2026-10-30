#!/usr/bin/env python3
"""Mo phong luu luong nguoi dung hop le (benign) truy cap ngau nhien co vao co ra.

Tinh nang:
  - Tao dai IP nguon ao (VD: 172.30.0.101 -> 172.30.0.135) tren eth0.
  - So luong nguoi dung dao dong tu nhien (khoang 15 - 30 users), den roi di (sessions).
  - Moi user gui request HTTP that bang ket noi TCP socket voi IP rieng biet.
  - Toc do duy tri an toan o muc ~12-25 pps tong the de he thong giu trang thai BENIGN.
  - Don dep IP sach se khi nhan SIGINT/SIGTERM.
"""
import argparse
import collections
import http.client
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time

URL_PATHS = [
    "/",
    "/index.html",
    "/about.html",
    "/contact",
    "/services",
    "/products",
    "/docs/overview",
    "/search?q=ddos",
    "/search?q=pbl3",
    "/search?q=security",
    "/api/status",
    "/assets/style.css",
    "/assets/app.js",
    "/assets/logo.png",
    "/assets/banner.jpg",
]

running = True
active_users = {}
lock = threading.Lock()
req_counter = 0


def cleanup_ips(ips):
    """Xoa cac IP alias da them vao eth0."""
    print(f"[*] Don dep {len(ips)} IP aliases...", flush=True)
    for ip in ips:
        subprocess.run(["ip", "addr", "del", f"{ip}/24", "dev", "eth0"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_ips(ips):
    """Them cac IP alias vao eth0 neu chua co."""
    for ip in ips:
        subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", "eth0"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def user_session(user_ip, target, port, available_ips):
    """Moi luong bieu dien 1 nguoi dung truy cap trang web qua session co thoi luong ngau nhien."""
    global req_counter
    # So trang nguoi nay se xem truoc khi roi di (co nguoi vao xem 2 trang roi ra, co nguoi xem 8 trang)
    pages_to_visit = random.randint(3, 9)

    for _ in range(pages_to_visit):
        if not running:
            break

        path = random.choice(URL_PATHS)
        try:
            conn = http.client.HTTPConnection(
                target, port,
                source_address=(user_ip, 0),
                timeout=3.0
            )
            # Thiet lap Header giong trinh duyet that
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            res = conn.getresponse()
            res.read(1024)
            conn.close()
            with lock:
                req_counter += 1
        except Exception:
            pass

        # Think-time giua cac lan click cua nguoi dung that (3.0s - 7.5s de doc noi dung/luot trang)
        think_time = random.uniform(3.0, 7.5)
        step = 0.2
        elapsed = 0.0
        while elapsed < think_time and running:
            time.sleep(step)
            elapsed += step

    # Nguoi dung ket thuc phien va roi khoi trang web (User Departure)
    with lock:
        if user_ip in active_users:
            del active_users[user_ip]
        available_ips.append(user_ip)


def main():
    global running
    ap = argparse.ArgumentParser()
    ap.add_argument("target", default="172.30.0.10", nargs="?", help="IP victim")
    ap.add_argument("-p", "--port", type=int, default=80, help="Port victim")
    ap.add_argument("--min-users", type=int, default=12, help="So user toi thieu")
    ap.add_argument("--max-users", type=int, default=24, help="So user toi da")
    ap.add_argument("--ip-start", type=int, default=101, help="Duoi IP bat dau (172.30.0.X)")
    ap.add_argument("--ip-count", type=int, default=35, help="So luong IP trong pool")
    args = ap.parse_args()

    # Sinh danh sach pool IP: 172.30.0.101 -> 172.30.0.135
    ip_pool = [f"172.30.0.{args.ip_start + i}" for i in range(args.ip_count)]

    # Xu ly tin hieu thoat de don dep IP
    def sig_handler(sig, frame):
        global running
        running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # Thiet lap IP tren interface container
    setup_ips(ip_pool)

    available_ips = collections.deque(ip_pool)
    target_count = random.randint(args.min_users, args.max_users)
    last_target_change = time.time()
    last_stat_time = time.time()
    last_req_count = 0

    print(json.dumps({
        "type": "sim_started",
        "pool_size": len(ip_pool),
        "min_users": args.min_users,
        "max_users": args.max_users,
        "target": args.target
    }), flush=True)

    try:
        while running:
            now = time.time()

            # Cu sau 15-25 giay, so luong khach muc tieu tu dong bien thien (co gio cao diem, co gio vang khach)
            if now - last_target_change > random.uniform(15.0, 25.0):
                target_count = random.randint(args.min_users, args.max_users)
                last_target_change = now

            # Neu so user hien tai it hon muc tieu, bo sung them user moi den (User Arrival)
            with lock:
                curr_active = len(active_users)

            if curr_active < target_count and available_ips:
                user_ip = available_ips.popleft()
                t = threading.Thread(
                    target=user_session,
                    args=(user_ip, args.target, args.port, available_ips),
                    daemon=True
                )
                with lock:
                    active_users[user_ip] = t
                t.start()
                # Khoang cach giua hai user lien tiep vao web (0.2s - 0.8s)
                time.sleep(random.uniform(0.2, 0.8))

            # Phat thong ke dinh ky moi 1.5 giay
            if now - last_stat_time >= 1.5:
                dt = now - last_stat_time
                with lock:
                    c_req = req_counter
                    c_active = len(active_users)
                cur_pps = (c_req - last_req_count) / max(dt, 0.001)
                last_req_count = c_req
                last_stat_time = now

                # In JSON ra stdout cho dashboard backend doc va truyen realtime ve browser
                print(json.dumps({
                    "type": "sim_stats",
                    "active_users": c_active,
                    "target_users": target_count,
                    "req_per_s": round(cur_pps, 1),
                    "total_reqs": c_req,
                    "running": True
                }), flush=True)

            time.sleep(0.1)

    finally:
        running = False
        print(json.dumps({"type": "sim_stopped", "running": False}), flush=True)
        cleanup_ips(ip_pool)


if __name__ == "__main__":
    main()
