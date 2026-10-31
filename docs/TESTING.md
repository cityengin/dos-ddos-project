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

**Kết quả kỳ vọng (Phân loại chính xác 100%, thời gian phát hiện ~0s, False Positives = 0):**

| Kịch bản | pps | syn/s | ack/s | n_src | H(src) | Nhãn chuẩn | Kết luận (Luật ngưỡng) |
|---|---|---|---|---|---|---|---|
| A — SYN 1 nguồn | ~300 | ~150 | 0 | 1 | 0.00 | DoS | `DoS [SYN flood]` |
| B — SYN 6 nguồn + Spoof | ~4000 | ~2000 | 0 | **~2300** | ~11.1 | DDoS | `DDoS [SYN flood]` |
| C — HTTP 6 nguồn (L7) | ~1800 | ~400 | ~1400 | 6 | ~2.58 | DDoS | `DDoS` (không gắn thẻ SYN) |

**Điểm kiểm tra mấu chốt:**
- Kịch bản A là **DoS** (`n_src = 1`); kịch bản B và C là **DDoS`.
- Các đòn SYN flood có `ack ≈ 0`; đòn HTTP flood có `ack >> syn`.
- Kịch bản B sử dụng 6 container attacker giả mạo IP nguồn ngẫu nhiên, tạo ra **hàng nghìn IP phân biệt trong một cửa sổ** (`H(src) ≈ 11` bits); kịch bản C sử dụng 6 máy thật của Docker nên `n_src = 6`.

---

### Các kịch bản biên khó tiệm cận ngưỡng (Scenarios D / E)

Chạy riêng bằng cờ `--only D` hoặc `--only E` — được thiết kế nhằm chứng minh hạn chế của luật ngưỡng và ưu thế của Học máy:

| Kịch bản | pps | syn/s | ack/s | n_src | Nhãn chuẩn | Kết luận Luật ngưỡng |
|---|---|---|---|---|---|---|
| D — SYN Spoof tốc độ thấp (Low-rate) | ~24 | ~24 | 0 | ~24 | DDoS | **Không cảnh báo** — dưới ngưỡng 40/25, luật **bỏ sót 100%** |
| E — HTTP 1 nguồn tải cao (Flash Crowd) | ~3000 | ~800 | ~2200 | 1 | BENIGN | **DoS** — vượt ngưỡng pps, luật **báo nhầm (False Alarm)** |

**Kết quả kỳ vọng:** Luật ngưỡng bỏ sót đòn tấn công D (False Negative) và báo động nhầm người dùng hợp lệ E (False Positive); trong khi đó mô hình Học máy (Mục 5) phân loại chính xác D là `DDoS` và E là `BENIGN`.

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
- Luật ngưỡng hoàn toàn nhầm lẫn giữa DoS và DDoS khi có lưu lượng nền hỗn hợp; trong khi Random Forest phân định chính xác tuyệt đối cả 3 lớp (`BENIGN`, `DoS`, `DDoS`).
- Thứ tự đặc trưng quan trọng nhất: `n_src`, `h_src`, `pps`, `rate_per_src`.

**Kết quả kỳ vọng khi chạy detector live (`--ml`):**
Mỗi dòng log hiển thị đồng thời cả kết luận của Luật ngưỡng lẫn Học máy: `ALERT | ML:<verdict>(<conf>)`.
- Bình thường $\to$ `BENIGN`
- SYN 1 nguồn $\to$ `DoS`
- SYN spoofing hoặc botnet phân tán $\to$ `DDoS`

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

Detector hỗ trợ hai engine: `--engine scapy` (mặc định) và `--engine ebpf` (tầng XDP trong kernel). Để chứng minh eBPF không bị rớt gói ở cường độ cao, gửi một số lượng gói tin cố định và so sánh:

```bash
# Khởi động detector ghi log CSV với engine eBPF:
docker exec -d detector python3 -u /app/detector.py --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --csv /app/bnd.csv

# Bơm chính xác 120,000 gói tin SYN spoofed từ 6 nguồn attacker:
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a hping3 -S -p 80 --rand-source --flood -c 20000 172.30.0.10; done

# Đợi khoảng 20 giây cho bão gói kết thúc, sau đó dừng detector:
docker exec detector pkill -f detector.py

# Tính tổng số gói tin mà detector ghi nhận được:
awk -F, 'NR>1{s+=$2} END{print s}' detection/bnd.csv
```

**Kết quả kỳ vọng:**
- Trong số 120,000 gói tin phát ra, engine **Scapy** chỉ đếm được **~57%** (chạm trần năng lực xử lý ở mức ~6.9k pps).
- Engine **eBPF** đếm chính xác **~95%** và ghi nhận đúng đỉnh lưu lượng thực tế (~30k pps).
- Ở tốc độ thấp, cả hai engine đều chính xác tuyệt đối (thử nghiệm 5,000 gói: eBPF đạt 4,986).

---

## 8. Cơ chế Phòng thủ Hủy gói Tự động (Closed-Loop XDP Drop, `--block`)

Mặc định detector chạy ở chế độ chỉ phát hiện (Detect-only). Khi thêm cờ `--block` (yêu cầu `--engine ebpf`), hệ thống kích hoạt cơ chế IPS tự động hủy gói trong kernel:

```bash
# Bật chặn tự động theo nguồn (hiệu quả với DoS/DDoS nguồn thật A / C):
docker exec -d detector python3 -u /app/detector.py --iface eth0 --pps 40 --syn 25 --victim 172.30.0.10 \
    --engine ebpf --block --block-pps 200 --block-ttl 5 --csv /app/blk.csv

# Kích hoạt đợt tấn công HTTP flood từ 6 container:
for a in attacker1 attacker2 attacker3 attacker4 attacker5 attacker6; do \
    docker exec -d $a python3 /app/http_flood.py 172.30.0.10 -p 80 -t 20 -d 16; done
```

**Kết quả kỳ vọng:**
- **Kịch bản C (HTTP 6 nguồn thật)**: Hệ thống nhận diện và đưa cả 6 IP vào danh sách chặn (`blocked_src=6`), lưu lượng tấn công sụp đổ hoàn toàn từ **~136,000 pps xuống chỉ còn ~242 pps**; người dùng hợp lệ bên ngoài vẫn nhận phản hồi 200 OK bình thường.
- **Kịch bản B (SYN Spoof ngẫu nhiên)**: Chặn theo IP nguồn đơn lẻ không có tác dụng do mỗi gói mang một IP mới. Khi bổ sung cờ giới hạn tốc độ SYN toàn cục `--block-syn-rate 2000`, hệ thống cắt bỏ thành công **~85%** lượng gói SYN rác.
- **Tính an toàn**: Danh sách chặn có thời gian sống TTL tự động giải phóng (không chặn vĩnh viễn); các máy khách gửi tốc độ thấp không bao giờ bị chặn nhầm.

---

## 9. Tấn công Công suất Tối đa (Line-Rate) & Tác động Thực tế

Dự án cung cấp hai mức cường độ phát tải: `paced` (có điều tiết tốc độ, phục vụ thu thập dữ liệu ML) và `max` (**tốc độ line-rate tối đa** qua `hping3 --flood` và `ab`, yêu cầu `--engine ebpf`).

```bash
# Chạy kịch bản tối đa với run_scenarios:
python experiments/run_scenarios.py --only A --intensity max --duration 10        # A: 1 nguồn hping3 --flood
python experiments/run_scenarios.py --only B --intensity max                      # B: 6 nguồn --rand-source --flood

# Chạy kịch bản tối đa với run_ddos.sh:
./run_ddos.sh syn  -i max            # hping3 --rand-source --flood
./run_ddos.sh http -i max            # ab -k -c 500

# Kiểm tra tác động thực tế lên máy nạn nhân (đo song song):
# 1. Đếm tốc độ gói thực tế vào card mạng eth0 của victim:
docker exec detector sh -c 'cat /proc/net/dev' | awk '/eth0:/{gsub(/:/," ");print "rx_packets="$3}'
# 2. Đo độ trễ phản hồi của khách hàng hợp lệ:
while :; do curl -s -m3 -o /dev/null -w '%{http_code} %{time_total}\n' http://localhost:8080/; sleep .25; done
```

**Kết quả đo đạc thực tế:**
- Dưới cường độ tấn công cực đại (A-max ~190k pps, B-max ~123k pps, C-max ~693k pps), card mạng `eth0` ghi nhận **0 gói tin bị rớt (0 rx drops)**, và người dùng hợp lệ vẫn nhận phản hồi **100% mã 200 OK** nhờ nhân Linux hiện đại kích hoạt cơ chế SYN Cookies và máy chủ Nginx tĩnh xử lý cực nhanh (độ trễ p95 chỉ tăng nhẹ từ 1ms lên 11ms).
- Khi bật cơ chế bảo vệ `--block`, các nguồn tấn công bị hủy tại XDP, lưu lượng giảm mạnh từ ~433k pps xuống ~28 pps và độ trễ trở lại mức 1ms lý tưởng.

---

## 10. Bảng Danh mục Kiểm tra Toàn diện (Quick Checklist)

- [ ] Cả 8 container ở trạng thái `Up`; trang web `http://localhost:8080` mở được bình thường.
- [ ] Trạng thái nghỉ (Baseline): 0 cảnh báo, 0 báo động giả.
- [ ] Phân loại chuẩn xác: Kịch bản A -> DoS, Kịch bản B -> DDoS, Kịch bản C -> DDoS, UDP DoS -> DoS, UDP DDoS / ICMP -> DDoS.
- [ ] Phân biệt đặc trưng gói: Tấn công SYN có `ack ≈ 0`; tấn công HTTP có `ack >> syn`; tấn công UDP có `udp_s` cao và gắn nhãn `[UDP flood]`; tấn công ICMP có `pps` cao với `syn_s = ack_s = udp_s = 0`.
- [ ] Chế độ ngưỡng thích nghi (Adaptive EWMA) phát hiện đúng và không báo nhầm khi lưu lượng nền biến thiên.
- [ ] Mô hình Học máy Random Forest cửa sổ (LORO) đạt độ chính xác 99.4%, phân tách chuẩn xác các trường hợp biên khó (D/E).
- [ ] Detector hiển thị đồng thời cả kết luận của Luật ngưỡng lẫn Học máy trên console và Dashboard.
- [ ] Engine eBPF đếm chính xác ~95% gói tin ở tốc độ cao (so với Scapy chỉ ~57%).
- [ ] Chế độ `--block` dập tắt thành công đòn tấn công nguồn thật (từ ~136k pps xuống ~242 pps) và cắt giảm 85% đòn SYN flood spoofing.
- [ ] Bảng điều khiển Web Dashboard cập nhật mượt mà theo thời gian thực tại `http://localhost:3000`.
