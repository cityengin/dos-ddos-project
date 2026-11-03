#!/usr/bin/env python3
"""Ve so do kien truc tong the he thong Phong thu DoS/DDoS (Lab PBL3) xuat ra assets/architecture.png.
Phan anh 100% kien truc hien tai:
  - 6 attacker container (attacker1..6)
  - 4 vector tan cong: L3 ICMP, L4 SYN (+Spoof), L4 UDP, L7 HTTP
  - Victim container (Nginx :80 -> :8080)
  - Detector container (chung network namespace voi victim):
    + Kernel space: eBPF / XDP Ingress Hook, BPF Maps, Closed-loop XDP_DROP & Token bucket
    + User space: Bo trich 10 dac trung, Luat + Adaptive EWMA + Random Forest ML
  - Web Dashboard (Node.js/Express + WebSocket :3000)
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "assets", "architecture.png")

plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Liberation Sans"]
plt.rcParams["axes.unicode_minus"] = False


def create_architecture_diagram():
    fig = plt.figure(figsize=(16, 9.8), dpi=150)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1600)
    ax.set_ylim(0, 980)
    ax.axis("off")

    # 1. Background
    bg = patches.Rectangle((0, 0), 1600, 980, facecolor="#090d16", zorder=0)
    ax.add_patch(bg)

    # Header Title Banner
    ax.text(800, 942, "KIẾN TRÚC TỔNG THỂ HỆ THỐNG MÔ PHỎNG & PHÒNG THỦ DoS/DDoS REAL-TIME",
            ha="center", va="center", fontsize=18, fontweight="bold", color="#ffffff")
    ax.text(800, 915, "Đồ án PBL3 · Mạng Docker Lab Cô lập (dos-lab 172.30.0.0/24) · Kernel eBPF/XDP · Random Forest ML · Dashboard Web",
            ha="center", va="center", fontsize=11, color="#94a3b8")

    # 2. Outer Docker Network Boundary (dos-lab)
    net_box = patches.FancyBboxPatch((40, 40), 1520, 845, boxstyle="round,pad=10,rounding_size=16",
                                    facecolor="#0f172a", edgecolor="#334155", linestyle="--", lw=1.8, zorder=1)
    ax.add_patch(net_box)
    ax.text(70, 860, "MẠNG DOCKER LAB CÔ LẬP: dos-lab (Bridge 172.30.0.0/24)",
            fontsize=12, fontweight="bold", color="#38bdf8", zorder=2)

    # =========================================================================
    # KHỐI 1: ATTACKER BOTNET CLUSTER (Bên trái)
    # =========================================================================
    atk_group = patches.FancyBboxPatch((65, 75), 390, 755, boxstyle="round,pad=8,rounding_size=12",
                                      facecolor="#1e1523", edgecolor="#dc2626", lw=1.5, zorder=2)
    ax.add_patch(atk_group)
    ax.text(260, 805, "CỤM MÁY TẤN CÔNG (BOTNET CLUSTER)", ha="center", fontsize=13, fontweight="bold", color="#f87171", zorder=3)
    ax.text(260, 782, "6 Docker Containers · CAP_NET_RAW / ADMIN", ha="center", fontsize=9.5, color="#cbd5e1", zorder=3)

    # 6 Attackers
    attk_configs = [
        ("attacker1", "172.30.0.21", "hping3 / ab / http_flood"),
        ("attacker2", "172.30.0.22", "hping3 / ab / http_flood"),
        ("attacker3", "172.30.0.23", "hping3 / ab / http_flood"),
        ("attacker4", "172.30.0.24", "hping3 / ab / http_flood"),
        ("attacker5", "172.30.0.25", "hping3 / ab / http_flood"),
        ("attacker6", "172.30.0.26", "hping3 / ab / http_flood"),
    ]
    y_start = 715
    for i, (name, ip, tools) in enumerate(attk_configs):
        y_pos = y_start - i * 66
        abox = patches.FancyBboxPatch((85, y_pos), 350, 52, boxstyle="round,pad=4,rounding_size=8",
                                     facecolor="#2d1a29", edgecolor="#ef4444", lw=1.2, zorder=3)
        ax.add_patch(abox)
        ax.text(105, y_pos + 32, f"● {name}", fontsize=11, fontweight="bold", color="#fecaca", zorder=4)
        ax.text(235, y_pos + 32, f"IP: {ip}", fontsize=10, fontfamily="monospace", color="#fca5a5", zorder=4)
        ax.text(105, y_pos + 12, f"Công cụ: {tools}", fontsize=8.5, color="#94a3b8", zorder=4)

    # Vector tấn công box
    vbox = patches.FancyBboxPatch((85, 95), 350, 205, boxstyle="round,pad=6,rounding_size=8",
                                 facecolor="#18111e", edgecolor="#f87171", linestyle=":", lw=1.2, zorder=3)
    ax.add_patch(vbox)
    ax.text(260, 275, "4 VECTOR TẤN CÔNG THỰC NGHIỆM", ha="center", fontsize=10.5, fontweight="bold", color="#fb7185", zorder=4)
    vectors = [
        ("• L4 TCP SYN Flood", "hping3 -S (--flood hoặc paced)", "#fbbf24"),
        ("• L4 IP Spoofing (DDoS)", "hping3 --rand-source (hàng nghìn IP)", "#f87171"),
        ("• L4 UDP Flood (Volumetric)", "hping3 --udp (đẩy nghẽn băng thông)", "#a78bfa"),
        ("• L3 ICMP Echo Flood", "hping3 --icmp (Ping flood kiệt quệ L3)", "#38bdf8"),
        ("• L7 HTTP Application Flood", "ab -k -c 100 / http_flood.py", "#34d399"),
    ]
    for idx, (title, desc, col) in enumerate(vectors):
        vy = 248 - idx * 34
        ax.text(98, vy, title, fontsize=9.5, fontweight="bold", color=col, zorder=4)
        ax.text(98, vy - 14, desc, fontsize=8, color="#94a3b8", zorder=4)

    # =========================================================================
    # KHỐI 2: ĐƯỜNG TRUYỀN TẤN CÔNG & LƯU LƯỢNG (Giữa)
    # =========================================================================
    # Arrows from Attackers to Victim
    arrow_atk = patches.FancyArrowPatch((460, 480), (595, 480),
                                        connectionstyle="arc3,rad=0",
                                        arrowstyle="simple,head_width=18,head_length=20",
                                        facecolor="#ef4444", edgecolor="#7f1d1d", lw=1.5, zorder=5)
    ax.add_patch(arrow_atk)
    ax.text(530, 520, "Lưu lượng Bão gói\nDoS / DDoS (pps cao)", ha="center", va="center",
            fontsize=9.5, fontweight="bold", color="#fca5a5", zorder=6,
            bbox=dict(boxstyle="round,pad=0.3", fc="#2d1217", ec="#ef4444", lw=1))

    # Arrow for Benign Users
    ax.text(530, 260, "Khách hàng hợp lệ\n(Benign Users HTTP)", ha="center", va="center",
            fontsize=9.5, fontweight="bold", color="#6ee7b7", zorder=6,
            bbox=dict(boxstyle="round,pad=0.3", fc="#062e24", ec="#10b981", lw=1))
    arrow_usr = patches.FancyArrowPatch((460, 220), (595, 220),
                                        connectionstyle="arc3,rad=-0.1",
                                        arrowstyle="simple,head_width=14,head_length=16",
                                        facecolor="#10b981", edgecolor="#064e3b", lw=1.2, zorder=5)
    ax.add_patch(arrow_usr)

    # =========================================================================
    # KHỐI 3: VICTIM & DETECTOR (CÙNG NETWORK NAMESPACE)
    # =========================================================================
    dual_netns = patches.FancyBboxPatch((600, 75), 520, 755, boxstyle="round,pad=8,rounding_size=12",
                                       facecolor="#0c2333", edgecolor="#0284c7", lw=1.8, zorder=2)
    ax.add_patch(dual_netns)
    ax.text(860, 805, "MÁY NẠN NHÂN (VICTIM) & DETECTOR", ha="center", fontsize=13.5, fontweight="bold", color="#38bdf8", zorder=3)
    ax.text(860, 782, "Chia sẻ Network Namespace: network_mode: 'service:victim' (Card eth0 chung)",
            ha="center", fontsize=9.5, color="#7dd3fc", zorder=3)

    # 3.1 NGINX VICTIM CONTAINER
    vic_box = patches.FancyBboxPatch((620, 580), 480, 185, boxstyle="round,pad=6,rounding_size=10",
                                    facecolor="#064e3b", edgecolor="#10b981", lw=1.5, zorder=3)
    ax.add_patch(vic_box)
    ax.text(640, 735, "MÁY NẠN NHÂN: victim (Nginx Container)", fontsize=13, fontweight="bold", color="#a7f3d0", zorder=4)
    ax.text(640, 712, "IP: 172.30.0.10:80  ➜  Host Port: http://localhost:8080",
            fontsize=10.5, fontfamily="monospace", color="#6ee7b7", zorder=4)
    ax.text(640, 680, "• Xử lý Web tĩnh siêu tốc (Linux Kernel SYN Cookies + Epoll)", fontsize=9.5, color="#d1fae5", zorder=4)
    ax.text(640, 655, "• Dịch vụ được đo đạc liên tục qua Health-Probe (đo RTT/Latency)", fontsize=9.5, color="#d1fae5", zorder=4)
    ax.text(640, 630, "• Hoàn toàn không rớt gói khi bật Closed-loop eBPF Filter", fontsize=9.5, color="#6ee7b7", fontweight="bold", zorder=4)
    ax.text(640, 600, "Cổng lắng nghe: TCP :80 (HTTP Web Service)", fontsize=9, fontstyle="italic", color="#a7f3d0", zorder=4)

    # 3.2 DETECTOR CONTAINER
    det_box = patches.FancyBboxPatch((620, 95), 480, 465, boxstyle="round,pad=6,rounding_size=10",
                                    facecolor="#0f2b46", edgecolor="#38bdf8", lw=1.6, zorder=3)
    ax.add_patch(det_box)
    ax.text(640, 532, "BỘ PHÁT HIỆN & PHÒNG THỦ: detector", fontsize=13, fontweight="bold", color="#bae6fd", zorder=4)
    ax.text(640, 510, "Container chạy song song với victim · Đặc quyền CAP_BPF, CAP_NET_ADMIN",
            fontsize=9, color="#93c5fd", zorder=4)

    # Sub-block: Kernel Space (eBPF/XDP)
    ebpf_box = patches.FancyBboxPatch((635, 335), 450, 160, boxstyle="round,pad=4,rounding_size=8",
                                     facecolor="#163758", edgecolor="#0284c7", lw=1.2, zorder=4)
    ax.add_patch(ebpf_box)
    ax.text(650, 470, "▶ TẦNG NHÂN LINUX (KERNEL SPACE - eBPF / XDP)", fontsize=10.5, fontweight="bold", color="#67e8f9", zorder=5)
    ax.text(650, 445, "• XDP Ingress Hook trên card eth0 (đếm chính xác 95% ở 30k+ pps)", fontsize=9, color="#e0f2fe", zorder=5)
    ax.text(650, 423, "• BPF Maps: counters[] (PERCPU), src_ips (cap 8192), dports[]", fontsize=9, color="#e0f2fe", zorder=5)
    ax.text(650, 401, "• Closed-loop IPS (--block): XDP_DROP theo IP blocklist (có TTL)", fontsize=9, color="#fef08a", fontweight="bold", zorder=5)
    ax.text(650, 379, "• Token Bucket SYN toàn cục (--block-syn-rate) xử lý IP Spoofing", fontsize=9, color="#fef08a", fontweight="bold", zorder=5)
    ax.text(650, 350, "Cơ chế: Đếm trước ➜ Hủy sau (Drop ngay tại Driver NIC, 0 CPU load)", fontsize=8.5, fontstyle="italic", color="#7dd3fc", zorder=5)

    # Sub-block: User Space (Engine phân tích)
    user_box = patches.FancyBboxPatch((635, 110), 450, 210, boxstyle="round,pad=4,rounding_size=8",
                                     facecolor="#122a44", edgecolor="#818cf8", lw=1.2, zorder=4)
    ax.add_patch(user_box)
    ax.text(650, 295, "▶ TẦNG NGƯỜI DÙNG (USER SPACE - DETECTOR ENGINE)", fontsize=10.5, fontweight="bold", color="#a5b4fc", zorder=5)
    ax.text(650, 273, "• Bộ trích xuất 10 Đặc trưng Cửa sổ (Sliding Window 1.0s / Stride 0.5s):", fontsize=9, color="#e0e7ff", zorder=5)
    ax.text(665, 255, "pps, syn_s, ack_s, udp_s, h_src", fontsize=8.5, fontfamily="monospace", color="#fbcfe8", zorder=5)
    ax.text(665, 240, "h_dport, n_src, syn_ratio, ack_syn_ratio, rate_per_src", fontsize=8.5, fontfamily="monospace", color="#fbcfe8", zorder=5)
    ax.text(650, 218, "• Bộ phán quyết 3 tầng song song:", fontsize=9, fontweight="bold", color="#e0e7ff", zorder=5)
    ax.text(665, 200, "1. Luật Ngưỡng (Threshold + Dominance top_share)", fontsize=8.5, color="#cbd5e1", zorder=5)
    ax.text(665, 183, "2. Ngưỡng Thích nghi động EWMA (μ + k·MAD)", fontsize=8.5, color="#cbd5e1", zorder=5)
    ax.text(665, 166, "3. Học máy Random Forest 10 đặc trưng (LORO 99.4% Acc)", fontsize=8.5, color="#38bdf8", fontweight="bold", zorder=5)
    ax.text(650, 142, "• Tự động kích hoạt cơ chế chặn closed-loop khi phát hiện tấn công", fontsize=8.5, color="#fde047", zorder=5)
    ax.text(650, 123, "• Đầu ra: JSON stream thời gian thực (stdout) + Log CSV", fontsize=8.5, color="#cbd5e1", zorder=5)

    # =========================================================================
    # KHỐI 4: WEB DASHBOARD & GIÁM SÁT (Bên phải)
    # =========================================================================
    dash_group = patches.FancyBboxPatch((1150, 75), 385, 755, boxstyle="round,pad=8,rounding_size=12",
                                       facecolor="#182033", edgecolor="#f59e0b", lw=1.6, zorder=2)
    ax.add_patch(dash_group)
    ax.text(1342, 805, "BẢNG ĐIỀU KHIỂN (SOC DASHBOARD)", ha="center", fontsize=13.5, fontweight="bold", color="#fbbf24", zorder=3)
    ax.text(1342, 782, "Node.js · Express · WebSocket · Trực quan hóa Real-time", ha="center", fontsize=9.5, color="#fde68a", zorder=3)

    # Dashboard subcomponents
    dash_box1 = patches.FancyBboxPatch((1170, 580), 345, 185, boxstyle="round,pad=5,rounding_size=8",
                                      facecolor="#232d44", edgecolor="#d97706", lw=1.2, zorder=3)
    ax.add_patch(dash_box1)
    ax.text(1185, 735, "Giao diện Web: http://localhost:3000", fontsize=11, fontweight="bold", color="#fef3c7", zorder=4)
    ax.text(1185, 710, "• 10 Thẻ Sparklines biểu đồ đặc trưng động", fontsize=9.5, color="#e2e8f0", zorder=4)
    ax.text(1185, 685, "• Banner Cảnh báo: BENIGN (Xanh) | DoS (Cam) | DDoS (Đỏ)", fontsize=9, color="#e2e8f0", zorder=4)
    ax.text(1185, 660, "• Hiển thị phán quyết Song song: Luật vs Học máy AI", fontsize=9.5, color="#38bdf8", fontweight="bold", zorder=4)
    ax.text(1185, 635, "• Bảng thống kê Top Active Sources (tỷ trọng lưu lượng)", fontsize=9.5, color="#e2e8f0", zorder=4)
    ax.text(1185, 605, "• Nút bấm kích hoạt Tấn công demo & Giả lập người dùng", fontsize=9, color="#fbbf24", zorder=4)

    dash_box2 = patches.FancyBboxPatch((1170, 360), 345, 200, boxstyle="round,pad=5,rounding_size=8",
                                      facecolor="#1c253b", edgecolor="#0ea5e9", lw=1.2, zorder=3)
    ax.add_patch(dash_box2)
    ax.text(1185, 532, "Luồng Dữ liệu Real-time (WebSocket)", fontsize=11, fontweight="bold", color="#7dd3fc", zorder=4)
    ax.text(1185, 505, "1. Detector đẩy 1 JSON/giây ra stdout", fontsize=9.5, color="#cbd5e1", zorder=4)
    ax.text(1185, 480, "2. Node.js backend lắng nghe qua child_process", fontsize=9.5, color="#cbd5e1", zorder=4)
    ax.text(1185, 455, "3. Broadcast tới các Client Web qua ws://", fontsize=9.5, color="#cbd5e1", zorder=4)
    ax.text(1185, 430, "4. Tự động kiểm tra sức khỏe Nginx (Health-check)", fontsize=9.5, color="#34d399", zorder=4)
    ax.text(1185, 405, "5. Nhật ký sự kiện bảo mật (Security Event Log)", fontsize=9.5, color="#cbd5e1", zorder=4)
    ax.text(1185, 378, "Độ trễ truyền nhận giao diện: < 20ms", fontsize=8.5, fontstyle="italic", color="#94a3b8", zorder=4)

    dash_box3 = patches.FancyBboxPatch((1170, 95), 345, 245, boxstyle="round,pad=5,rounding_size=8",
                                      facecolor="#182338", edgecolor="#6366f1", lw=1.2, zorder=3)
    ax.add_patch(dash_box3)
    ax.text(1185, 312, "KẾT QUẢ & CƠ CHẾ ĐÃ KIỂM CHỨNG", fontsize=11, fontweight="bold", color="#c7d2fe", zorder=4)
    results = [
        ("• Độ chính xác Học máy (LORO):", "99.4% (F1 = 0.996)", "#38bdf8"),
        ("• Khắc phục ca biên khó D & E:", "Bắt trọn Low-rate & Flash crowd", "#a7f3d0"),
        ("• Hiệu quả đếm gói eBPF/XDP:", "95% gói tại line-rate (vs Scapy 57%)", "#fef08a"),
        ("• Cơ chế XDP_DROP Closed-loop:", "Giảm từ 433k pps xuống 28 pps", "#fca5a5"),
        ("• Độ trễ người dùng hợp lệ:", "Duy trì 100% HTTP 200 OK (< 11ms)", "#86efac"),
        ("• Đa dạng Vector thực nghiệm:", "TCP SYN, UDP, ICMP Ping, HTTP L7", "#fdba74"),
    ]
    for idx, (lbl, val, c_val) in enumerate(results):
        ry = 285 - idx * 34
        ax.text(1185, ry, lbl, fontsize=9, color="#e2e8f0", zorder=4)
        ax.text(1185, ry - 14, val, fontsize=8.5, fontweight="bold", color=c_val, zorder=4)

    # Arrow from Detector to Dashboard (Direct into dash_box2 at y=460)
    arrow_stream = patches.FancyArrowPatch((1100, 460), (1165, 460),
                                           connectionstyle="arc3,rad=0",
                                           arrowstyle="simple,head_width=15,head_length=18",
                                           facecolor="#f59e0b", edgecolor="#78350f", lw=1.2, zorder=5)
    ax.add_patch(arrow_stream)
    ax.text(1132, 492, "JSON Stream\n(stdout/pipe)", ha="center", va="center",
            fontsize=8.5, fontweight="bold", color="#fde68a", zorder=6,
            bbox=dict(boxstyle="round,pad=0.25", fc="#3b2207", ec="#f59e0b", lw=0.8))

    # Save figure
    fig.savefig(OUT_PATH, dpi=150)
    plt.close(fig)
    print(f"[*] Da tao xong so do kien truc: {OUT_PATH}")


if __name__ == "__main__":
    create_architecture_diagram()
