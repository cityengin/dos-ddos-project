# Hướng dẫn Kiểm thử & Xác minh Toàn diện (Testing & Verification Guide)

Tài liệu này hướng dẫn chi tiết cách kiểm thử và xác minh từng thành phần của dự án, kèm theo kết quả kỳ vọng cho từng trường hợp thử nghiệm.
Mọi bài test chỉ được phép thực hiện nhắm vào container `victim` của chính phòng lab.

---

## 0. Yêu cầu Tiên quyết (Prerequisites)

Khởi động toàn bộ môi trường phòng thí nghiệm trên máy tính của bạn:

```bash
docker compose up -d --build
docker compose ps          # kỳ vọng: victim, detector, attacker1..6 đều ở trạng thái "Up"
pip install matplotlib pandas scikit-learn joblib   # trên máy host phục vụ phân tích & ML
```

Mở trình duyệt truy cập `http://localhost:8080` -> Trang chào mừng của Nginx hiển thị bình thường (máy nạn nhân đang hoạt động).

---

## 1. Lưu lượng Nền cơ sở (Baseline) — Không có tấn công

Chạy mô-đun phát hiện trong khoảng 15 giây khi không có lưu lượng tấn công:

```bash
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10
```

**Kết quả kỳ vọng:** Mọi dòng log hiển thị `pps=0 syn=0 ack=0`, cột `ALERT` để trống (không có cảnh báo giả / zero false positives). Nhấn `Ctrl-C` để dừng.

---

## 2. Các Kịch bản Phát hiện Tiêu chuẩn A / B / C

Cách chạy tự động nhanh nhất (khuyến nghị) — tự động chạy baseline + 3 kịch bản tấn công, xuất file log CSV và siêu dữ liệu:

```bash
python experiments/run_scenarios.py
python analysis/metrics.py detection/A.csv --truth DoS
python analysis/metrics.py detection/B.csv --truth DDoS
python analysis/metrics.py detection/C.csv --truth DDoS
```

**Kết quả kỳ vọng (phát hiện ngay cửa sổ đầu tiên, không cảnh báo ngoài thời gian tấn công).** Giá trị dưới đây là trung vị của lần chạy lưu trong `results/final/` (31/10/2026); con số cụ thể thay đổi theo máy:

| Kịch bản | pps | syn/s | ack/s | n_src | H(src) | Nhãn chuẩn | Kết luận (Luật ngưỡng) |
|---|---|---|---|---|---|---|---|
| A — SYN 1 nguồn | ~350 | ~175 | 0 | 1 | 0.00 | DoS | `DoS [SYN flood]` (10/11 cửa sổ) |
| B — SYN 6 nguồn + Spoof | ~2500 | ~2500 | 0 | **~2500** | ~11.3 | DDoS | `DDoS [SYN flood]` (10/10) |
| C — HTTP 6 nguồn (L7) | ~1400 | ~0 | ~1400 | 6 | 2.58 | DDoS | `DDoS` (10/10, không gắn thẻ SYN) |

Ở A, `pps ≈ 2 × syn/s` vì mỗi SYN-ACK của victim bị kernel máy tấn công trả lại bằng một gói RST (hping3 tạo SYN bằng raw socket).

**Điểm kiểm tra mấu chốt:**
- Kịch bản A là **DoS** (`n_src = 1`); kịch bản B và C là **DDoS`.
- Các đòn SYN flood có `ack ≈ 0`; đòn HTTP flood có `ack >> syn`.
- Kịch bản B sử dụng 6 container attacker giả mạo IP nguồn ngẫu nhiên, tạo ra **hàng nghìn IP phân biệt trong một cửa sổ** (`H(src) ≈ 11` bits); kịch bản C sử dụng 6 máy thật của Docker nên `n_src = 6`.

---

### Các kịch bản biên khó tiệm cận ngưỡng (Scenarios D / E)

Chạy riêng bằng cờ `--only D` hoặc `--only E` — được thiết kế nhằm chứng minh hạn chế của luật ngưỡng và ưu thế của Học máy:

| Kịch bản | pps | syn/s | ack/s | n_src | Nhãn chuẩn | Kết luận Luật ngưỡng |
|---|---|---|---|---|---|---|
| D — SYN Spoof tốc độ thấp (2 × 12 pps) | ~24–28 | ~24–28 | 0 | ~24–28 | DDoS | **Sát ngưỡng 25 SYN/s** — tùy lần chạy, luật bỏ sót hoặc bắt được (`results/final/D.csv`: 28 SYN/s → bắt 8/9 cửa sổ) |
| E — HTTP 1 nguồn tải cao | ~2200 | ~0 | ~2200 | 1 | BENIGN | **DoS** — vượt ngưỡng pps, luật **báo nhầm** (8/9 cửa sổ) |

**Kết quả thực đo (`results/final/`):** Học máy (Mục 5) kết luận D là `DDoS` ở 9/9 cửa sổ. Với E, **ML cũng kết luận `DoS`** ở 8/9 cửa sổ: nhìn từ victim, một máy gửi HTTP ~2200 pps giống hệt HTTP flood 1 nguồn (kiểu lưu lượng mang nhãn DoS trong dữ liệu huấn luyện), nên đặc trưng theo gói không tách được hai trường hợp này. Ưu thế của ML với tấn công dưới ngưỡng thể hiện trên tập dữ liệu huấn luyện (Mục 5: 163/180 cửa sổ dưới ngưỡng, luật 0/180).

---

### Kịch bản Tấn công UDP Flood (Vector L4 Volumetric)

Chạy thủ công hoặc thông qua kịch bản điều phối:

```bash
# 1 nguồn (DoS) — chạy thủ công bằng hping3 (~400 pps):
docker exec attacker1 hping3 --udp -p 80 -i u2500 172.30.0.10

# 6 nguồn, giả mạo IP (DDoS) — chạy qua script điều phối:
./run_ddos.sh udp            # chế độ điều tiết (paced hping3 --udp -i uN)
./run_ddos.sh udp -i max     # chế độ tối đa -> hping3 --udp --flood
```

**Kết quả kỳ vọng:** Cột `udp_s` tăng vọt trong khi `syn_s`/`ack_s` ≈ 0, cảnh báo được gắn thẻ `[UDP flood]`. Các kịch bản SYN/HTTP khác không bị ảnh hưởng (`udp_s = 0`).

---

### Kịch bản Tấn công ICMP Ping Flood (Vector L3 Echo Flood)

Chạy thủ công hoặc thông qua kịch bản điều phối:

```bash
# 1 nguồn (DoS) — chạy thủ công bằng hping3:
docker exec attacker1 hping3 --icmp -i u2500 172.30.0.10

# 6 nguồn, giả mạo IP (DDoS) — chạy qua script điều phối:
./run_ddos.sh icmp           # chế độ điều tiết (paced hping3 --icmp -i uN)
./run_ddos.sh icmp -i max    # chế độ tối đa -> hping3 --icmp --flood
```

**Kết quả kỳ vọng:** Cột `pps` tăng vọt trong khi `syn_s = 0, ack_s = 0, udp_s = 0`. Với chế độ giả mạo IP (DDoS), `n_src` tăng hàng nghìn IP trong 1 giây, entropy nguồn `H(src) > 10` bits, hệ thống cảnh báo DDoS và mô hình Học máy phân loại chính xác DDoS (độ tin cậy 99%).

---

### Kịch bản Tấn công DNS Amplification (Phản xạ & Khuếch đại)

Khác các flood trực tiếp: attacker nhắm vào **reflector `172.30.0.30`** và **giả mạo IP nguồn = victim**, nên phản hồi khuếch đại dội về victim.

```bash
# Chạy qua script điều phối (attacker hỏi reflector, spoof victim):
python experiments/run_scenarios.py --only DNS --duration 10

# Hoặc thủ công từ 1 attacker:
docker exec -d attacker1 python3 /app/dns_amp.py 172.30.0.30 --victim 172.30.0.10 --pps 300
```

**Kết quả kỳ vọng:** Cột `dns_s` (gói UDP source-port 53) tăng cao, cảnh báo gắn nhãn `[DNS amp]`. Vì victim chỉ thấy **1 reflector thật** nên phân loại **DoS** (`n_src = 1`, `top = 1.00`). Hệ số khuếch đại đo được ~40–50× (truy vấn ~40 byte → phản hồi ~2.5 KB). Các kịch bản khác không bị ảnh hưởng (`dns_s = 0`).

---

## 3. Kiểm thử Ngưỡng Thích nghi (Adaptive EWMA)

```bash
# Chạy detector với chế độ thích nghi trên máy nạn nhân:
docker exec -it detector python3 /app/detector.py --adaptive --victim 172.30.0.10

# Mở terminal khác và kích hoạt tấn công bất kỳ:
./run_ddos.sh syn

# Chạy kịch bản đánh giá so sánh trên dữ liệu chuỗi tổng hợp:
python experiments/adaptive_eval.py      # xuất đồ thị -> assets/adaptive_eval.png
```

**Kết quả kỳ vọng:** Chế độ live tự học đường cơ sở trong ~8 giây đầu (không báo động), sau đó lập tức phát hiện tấn công khi lưu lượng tăng đột biến. Script `adaptive_eval.py` chứng minh: Ngưỡng cố định thấp bị báo động giả khi lưu lượng nền tăng; ngưỡng cố định cao bị bỏ sót tấn công; **ngưỡng thích nghi EWMA vừa bắt trọn tấn công vừa triệt tiêu báo động giả**.

---

## 4. Học máy — Đánh giá Cấp Luồng trên CICDDoS2019 (Giai đoạn đầu)

Các script huấn luyện cấp luồng (`ml/train.py`, `ml/make_synthetic.py`) đã hoàn thành sứ mệnh kiểm chuẩn và được lưu trữ lịch sử:
- Trên bộ dữ liệu thực tế **CICDDoS2019** (~131k luồng / 63 đặc trưng / 13 họ tấn công): Điểm F1 phát hiện tấn công tăng từ **~0.60** (luật ngưỡng đơn) lên **0.999** (RandomForest) và **0.996** (HistGradientBoosting); độ chính xác phân loại họ tấn công đạt **~93%**, macro-F1 **~0.74**.
- Mô hình Học máy trực tiếp phục vụ phòng thủ thời gian thực của dự án là **mô hình cấp Cửa sổ (Window-level)** được mô tả ở Mục 5 dưới đây.

---

## 5. Học máy Cấp Cửa sổ Trực tiếp trên Detector (`--ml`)

Thu thập tập dữ liệu và huấn luyện mô hình (trên host), sau đó chạy detector kèm cờ `--ml` để phân loại song song với luật ngưỡng:

```bash
# 1. Bắt ít nhất 3 phiên PCAP ở các thời điểm khác nhau (1 pcap = 1 run cho LORO):
python3 experiments/capture_session.py --session s1     # ~10 phút -> detection/cap/s1.pcap + .timeline
python3 ml/pcap_to_windows.py detection/cap/s1.pcap --timeline detection/cap/s1.timeline --run s1
# Lặp lại tương tự cho phiên s2, s3 -> dữ liệu nối vào ml/data/windows_pcap.csv

# 2. Huấn luyện mô hình Random Forest cửa sổ:
.venv/bin/python ml/train_window.py                     # xuất ra detection/window_model.joblib

# 3. Khởi chạy detector live với mô hình AI:
docker exec -it detector python3 /app/detector.py --pps 40 --syn 25 \
    --victim 172.30.0.10 --ml /app/window_model.joblib

# 4. Mở terminal khác để phát tải tấn công:
./run_ddos.sh syn
```

**Kết quả kỳ vọng (`train_window.py`, tập dữ liệu PCAP 3 lần chạy với 3,362 cửa sổ, kiểm định LORO):**
- Điểm F1 phát hiện nhị phân: **~0.88 (Luật ngưỡng) vs 0.996 (Random Forest)**.
- Độ chính xác đa lớp (Accuracy): **~61.1% (Luật ngưỡng) vs 99.4% (Random Forest)**.
- Macro-F1 3 lớp: **0.477 (Luật ngưỡng) vs 0.994 (Random Forest)**. Luật đường cơ sở (`n_src ≥ 2` → DDoS, không có điều kiện `top_share`) xếp 82% cửa sổ DoS vào DDoS vì luôn có một nguồn benign chạy nền, và báo nhầm 363/1124 cửa sổ BENIGN (Random Forest: 1/1124).
- Cửa sổ tấn công dưới ngưỡng (`pps < 40` và `syn_s < 25`): luật 0/180, Random Forest **163/180 (90.6%)**.
- Thứ tự đặc trưng quan trọng nhất: `n_src` (0.28), `h_src` (0.25), `pps` (0.15), `rate_per_src` (0.11).

**Kết quả kỳ vọng khi chạy detector live (`--ml`):**
Mỗi dòng log hiển thị đồng thời cả kết luận của Luật ngưỡng lẫn Học máy: `ALERT | ML:<verdict>(<conf>)`.
- Bình thường $\to$ `BENIGN`
- SYN 1 nguồn $\to$ `DoS` (độ tin cậy ~0.6)
- SYN spoofing hoặc botnet phân tán $\to$ `DDoS` (~0.9–1.0)
- Lưu ý (đo 14/11/2026): với lưu lượng hợp lệ của `benign_dynamic_users.py` (12–24 người dùng ảo, không có trong dữ liệu huấn luyện), luật không báo nhầm nhưng ML báo nhầm `DoS` ở 5/30 cửa sổ — mô hình cần huấn luyện lại khi lưu lượng nền thay đổi.

---

## 6. Kiểm thử Giao diện Bảng điều khiển (Dashboard Console)

Khởi động bảng điều khiển web:

```bash
cd dashboard && npm install && npm start      # truy cập http://127.0.0.1:3000
```

Mở trình duyệt tại `http://localhost:3000` và xác minh từng trường hợp:

| Hành động | Kết quả kỳ vọng trên giao diện |
|---|---|
| **Nghỉ (Không tấn công)** | Trạng thái **BENIGN / SAFE**, biểu tượng máy nạn nhân xanh lá, các ô pps/syn bằng 0 |
| **Bấm kịch bản A (DoS SYN)** | Banner Cam `DoS [SYN flood]`, máy nạn nhân chuyển màu cam, đường truyền từ attacker1 phát sáng |
| **Bấm kịch bản B (DDoS SYN Spoof)** | Banner Đỏ `DDoS [SYN flood]`, n_src nhảy lên hàng nghìn, H(src) ~11, cả 6 đường truyền rực đỏ |
| **Bấm kịch bản C (DDoS HTTP)** | Banner Đỏ `DDoS`, ack/s >> syn/s, n_src=6, 6 đường kết nối botnet hoạt động |
| **Bấm Dừng tấn công (Stop)** | Trở về trạng thái SAFE / BENIGN trong vòng 2 giây |

Hộp trạng thái hiển thị song song **hai dòng**: `rule: <X>` (Luật ngưỡng) và `ML: <Y> · <conf>%` (Mô hình AI Random Forest kèm độ tự tin). Kiểm tra sức khỏe dịch vụ web (**Service Health**) cập nhật liên tục độ trễ và mã phản hồi HTTP.

---

## 7. Engine Bắt gói: So sánh Scapy vs eBPF ở Tốc độ Line-Rate

Detector hỗ trợ hai engine: `--engine scapy` (mặc định) và `--engine ebpf` (chương trình XDP trong kernel, chế độ generic). Để so sánh độ chính xác, cho 6 attacker phát UDP flood **không giả mạo** ở tốc độ tối đa trong một khoảng thời gian cố định, rồi so số gói detector đếm được với bộ đếm `rx_packets` của chính card `eth0`:

```bash
# Detector ghi CSV với engine cần đo (lặp lại với --engine scapy):
docker exec -d detector python3 -u /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --csv /app/cnt.csv
sleep 8
rx0=$(docker exec victim cat /proc/net/dev | awk -F: '/eth0:/{split($2,a," "); print a[2]}')

# Lưu ý: hping3 --flood BỎ QUA tham số -c, phải giới hạn bằng timeout:
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a timeout 8 hping3 --udp -p 80 -q --flood 172.30.0.10; done
sleep 14
rx1=$(docker exec victim cat /proc/net/dev | awk -F: '/eth0:/{split($2,a," "); print a[2]}')
docker exec detector pkill -f detector.py

echo "eth0 nhận: $((rx1-rx0))"; awk -F, 'NR>1{s+=$2} END{print "detector đếm:", s}' detection/cnt.csv
```

**Kết quả đo ngày 14/11/2026** (i7-12700H, kernel 7.0, ~1.1–1.2 triệu pps):

| Engine | `eth0` thực nhận | Detector đếm được | Tỷ lệ | Đỉnh thấy được |
|---|---|---|---|---|
| Scapy | 8,647,512 | 80,039 | **0.9%** | ~10k pps |
| eBPF/XDP | 9,767,022 | 9,764,336 | **≈100%** | ~1.24 triệu pps |

> [!NOTE]
> Phiên bản trước của mục này dùng `hping3 --flood -c 20000` và giả định "120,000 gói"; vì `--flood` bỏ qua `-c`, số gói thực phát lớn hơn nhiều, nên các tỷ lệ cũ (Scapy ~57%, eBPF ~95%) không còn dùng. Bản đo mới dùng UDP không giả mạo để toàn bộ lưu lượng nằm trong lab.

---

## 8. Cơ chế Phòng thủ Hủy gói Tự động (Closed-Loop XDP Drop, `--block`)

Mặc định detector chạy ở chế độ chỉ phát hiện. Khi thêm cờ `--block` (yêu cầu `--engine ebpf`), nguồn vượt `--block-pps` bị đưa vào blocklist có TTL và gói của nó bị `XDP_DROP`; các cờ `--block-syn-rate/--block-udp-rate/--block-icmp-rate` bật token bucket theo giao thức cho tấn công giả mạo nguồn.

> [!IMPORTANT]
> Xóa file điều khiển cũ trước khi đo: `docker exec detector rm -f /tmp/detector_block`. Nếu file này còn giá trị `1` từ lần gạt công tắc trên dashboard trước đó, detector sẽ tự bật chặn ngay khi khởi động, kể cả khi không có `--block`.

```bash
# Ví dụ kịch bản C ở mức tối đa, bật chặn:
docker exec -d detector python3 -u /app/detector.py --iface eth0 --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --block --block-pps 300 --block-ttl 5 --csv /app/blk.csv
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a timeout 10 ab -k -c 500 -t 9 -n 100000000 http://172.30.0.10/; done

# Song song, đo khách hợp lệ từ host (mỗi 0.2 s, timeout 2 s):
while :; do curl -s -m2 -o /dev/null -w '%{http_code} %{time_total}\n' http://localhost:8080/; sleep .2; done
```

**Kết quả đo ngày 14/11/2026** (mỗi kịch bản 10 giây ở mức tối đa, chạy hai lần: chỉ phát hiện và `--block`; khi không tấn công, p95 của khách hợp lệ ≈ 2.6–3.8 ms):

| Kịch bản (mức tối đa) | Lưu lượng tấn công (trung bình) | Chỉ phát hiện: khách hợp lệ | Bật chặn: gói tấn công bị bỏ | Bật chặn: khách hợp lệ |
|---|---|---|---|---|
| **A** — `hping3 -S --flood`, 1 nguồn | ~235k pps (đỉnh ~265k) | 100% 200 OK, p95 2.9 ms | **99.9%** (`blocked_src=1`) | 100%, p95 3.3 ms |
| **C** — `ab -k -c 500` × 6 nguồn | ~565k pps (đỉnh ~734k) | 100% 200 OK, p95 8.1 ms | Lưu lượng sụp còn **~4.5k pps** (`blocked_src=6`) | 100%, p95 3.5 ms |
| **DNS amp** — `dns_amp.py --pps 0` | ~2.3k pps | 100% 200 OK, p95 2.0 ms | **94.9%** (`blocked_src=1`) | 100%, p95 2.4 ms |

- **Chặn theo nguồn** hiệu quả với tấn công từ nguồn thật (A, C) và với DNS amplification (victim chỉ thấy một số ít reflector thật).
- **Tấn công giả mạo nguồn (B, U, I):** chặn theo IP vô dụng vì mỗi gói mang một IP mới; token bucket theo giao thức xử lý được — lần đo trước ghi nhận ~85% SYN bị bỏ với `--block-syn-rate 2000`, ~90% UDP với `--block-udp-rate 1000`, ~95% ICMP với `--block-icmp-rate 500` (`blocked_src=0`). Đánh đổi: gói hợp lệ cùng giao thức cũng bị bỏ khi tổng vượt giới hạn. Các số này **chưa được đo lại**: mạng `dos-lab` không `internal` và host bật chuyển tiếp gói, nên SYN-ACK/ICMP mà victim gửi tới IP giả có thể đi ra Internet — chỉ chạy B/U/I khi host đã ngắt Internet.
- **Tính an toàn:** Danh sách chặn có TTL tự hết hạn (không chặn vĩnh viễn); khách gửi tốc độ thấp không bị chặn nhầm.

---

## 9. Tấn công Công suất Tối đa (Line-Rate) & Tác động Thực tế

Dự án cung cấp hai mức cường độ phát tải: `paced` (có điều tiết tốc độ, phục vụ thu thập dữ liệu ML) và `max` (**tốc độ tối đa** qua `hping3 --flood` và `ab`, yêu cầu `--engine ebpf`).

```bash
# Chạy kịch bản tối đa với run_scenarios:
python experiments/run_scenarios.py --only A --intensity max --duration 10        # A: 1 nguồn hping3 --flood
python experiments/run_scenarios.py --only C --intensity max --duration 10        # C: 6 nguồn ab -k -c 500

# Chạy kịch bản tối đa với run_ddos.sh:
./run_ddos.sh http -i max            # ab -k -c 500

# Đo khách hợp lệ song song (từ host):
while :; do curl -s -m2 -o /dev/null -w '%{http_code} %{time_total}\n' http://localhost:8080/; sleep .2; done
```

**Kết quả đo ngày 14/11/2026** (chi tiết ở bảng Mục 8):
- Ở chế độ chỉ phát hiện, A-max (~235k pps), C-max (~565k pps) và DNS-max (~2.3k pps) đều **không làm gián đoạn dịch vụ**: khách hợp lệ nhận 100% phản hồi 200 OK; tác động lớn nhất là p95 trong kịch bản HTTP tăng từ ~2.6 ms lên 8.1 ms. Nguyên nhân: SYN cookies của kernel chống cạn hàng đợi SYN, nginx phục vụ trang tĩnh rất nhanh, và lab Docker chạy trên một máy nên **không có giới hạn băng thông** để tấn công thể tích làm nghẽn.
- Khi bật `--block`, A-max bị bỏ 99.9% tại XDP, C-max sụp từ ~565k xuống ~4.5k pps và p95 của khách hợp lệ về lại ~3.5 ms.
- B-max (SYN giả mạo `--flood`) không được đo lại vì lý do nêu ở Mục 8.

---

## 10. Bảng Danh mục Kiểm tra Toàn diện (Quick Checklist)

- [ ] Cả 8 container ở trạng thái `Up`; trang web `http://localhost:8080` mở được bình thường.
- [ ] Trạng thái nghỉ (Baseline): 0 cảnh báo, 0 báo động giả.
- [ ] Phân loại chuẩn xác: Kịch bản A -> DoS, Kịch bản B -> DDoS, Kịch bản C -> DDoS, UDP DoS -> DoS, UDP DDoS / ICMP -> DDoS.
- [ ] Phân biệt đặc trưng gói: Tấn công SYN có `ack ≈ 0`; tấn công HTTP có `ack >> syn`; tấn công UDP có `udp_s` cao và gắn nhãn `[UDP flood]`; tấn công ICMP có `pps` cao với `syn_s = ack_s = udp_s = 0`; DNS amplification có `dns_s` cao (UDP sport 53) và gắn nhãn `[DNS amp]`.
- [ ] Chế độ ngưỡng thích nghi (Adaptive EWMA) phát hiện đúng và không báo nhầm khi lưu lượng nền biến thiên.
- [ ] Mô hình Học máy Random Forest cửa sổ (LORO) đạt độ chính xác 99.4%, F1 0.996 (luật đường cơ sở 0.883), bắt 163/180 cửa sổ dưới ngưỡng; kịch bản E vẫn bị cả luật lẫn ML kết luận DoS (giới hạn đã biết).
- [ ] Detector hiển thị đồng thời cả kết luận của Luật ngưỡng lẫn Học máy trên console và Dashboard.
- [ ] Engine eBPF đếm ≈100% gói tin ở ~1.2 triệu pps (so với `rx_packets` của eth0), Scapy chỉ ~1%.
- [ ] Chế độ `--block` bỏ 99.9% SYN flood 1 nguồn (A-max), làm HTTP flood 6 nguồn (C-max) sụp từ ~565k xuống ~4.5k pps, bỏ 94.9% phản xạ DNS; khách hợp lệ vẫn 100% 200 OK.
- [ ] Bảng điều khiển Web Dashboard cập nhật mượt mà theo thời gian thực tại `http://localhost:3000`.
