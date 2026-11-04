# Hướng dẫn Demo Thực nghiệm 3 Máy Thật (1 Victim + 2 Attacker)

Cẩm nang chi tiết hướng dẫn thiết lập, phân chia công việc và kịch bản thực nghiệm DoS/DDoS trên **3 laptop vật lý kết nối chung mạng Wi-Fi/LAN**.

> ⚠️ **LƯU Ý AN TOÀN**: Toàn bộ thử nghiệm chỉ được phép thực hiện trong môi trường lab cô lập, chỉ nhắm vào máy `victim` của chính mình trên mạng Wi-Fi riêng. Tuyệt đối không phát lưu lượng vào bất kỳ hệ thống nào khác.

---

## ⚡ BƯỚC BẮT BUỘC ĐẦU TIÊN: Đồng bộ mã nguồn (Trên CẢ 3 Máy)

Trước khi chuẩn bị buổi thuyết trình, trên **CẢ 3 laptop**, mở terminal và chạy lệnh đồng bộ mã nguồn mới nhất từ GitHub:
```bash
cd ~/dos-ddos-project && git pull origin main
```
*Việc này đảm bảo cả 3 máy đều có đầy đủ giao diện Attacker Web Console (:4000), thanh gạt phòng thủ IPS, mô hình ML và cấu hình DNS Reflector mới nhất.*

---

## 1. Chuẩn bị Mạng & Địa chỉ IP (Pre-flight Setup)

### 1.1. Kết nối mạng Wi-Fi chung
- Cả 3 laptop kết nối vào cùng một mạng Wi-Fi.
- **Khuyến nghị thực tế**: Nên dùng **1 điện thoại 4G/5G phát Hotspot Wi-Fi** cho cả 3 máy kết nối vào. Mạng Hotspot cá nhân không bị chặn bởi tường lửa (firewall) hoặc chính sách chặn gói tin bất thường (AP/client isolation) của mạng trường học.

### 1.2. Xác định IP và tên card Wi-Fi của từng máy
Trên mỗi máy, mở terminal chạy lệnh:
```bash
hostname -I
# hoặc: ip -brief addr
```
Ghi lại IP và tên card mạng Wi-Fi (thường là `wlan0` hoặc `wlp...`):

| Vai trò | Máy | Địa chỉ IP ví dụ | Chức năng trong buổi Demo | Cần cài đặt |
|---|---|---|---|---|
| **VICTIM** | 1 laptop (nối máy chiếu) | `192.168.1.100` | • Nginx Web Server (:80)<br>• `detector.py` giám sát card Wi-Fi<br>• SOC Defense Console (:3000) | `nginx`, `python3-scapy`, `tcpdump`, `nodejs`, `npm` |
| **ATTACKER 1** | 1 laptop | `192.168.1.50` | • Traffic Generator Console (:4000)<br>• DNS Reflector BIND9 container (:53) | `hping3`, `apache2-utils`, `docker`, `nodejs` |
| **ATTACKER 2** | 1 laptop | `192.168.1.51` | • Traffic Generator Console (:4000) | `hping3`, `apache2-utils`, `nodejs` |

---

## 2. Giải đáp: "IP DNS Reflector lấy ở đâu?"

DNS Reflector là máy chủ DNS trung gian nhận gói truy vấn DNS nhỏ (EDNS0) bị giả mạo IP nguồn của victim và phản hồi gói tin lớn (3.5–4 KB) dội ngược về victim nhằm gây nghẽn băng thông:

1. **Khi demo trên máy thật (3 Laptop cùng mạng Wi-Fi):**
   - Bạn tận dụng ngay **Laptop Attacker 1** để chạy container BIND9 Reflector có sẵn trong dự án.
   - Khi đó: **IP DNS Reflector chính là Địa chỉ IP Wi-Fi của Laptop Attacker 1** (ví dụ: `192.168.1.50`).
   - Cả 2 máy Attacker 1 và Attacker 2 sẽ điền IP này vào ô cấu hình trên giao diện web.
2. **Khi demo giả lập trên 1 máy đơn (Docker Lab):**
   - IP DNS Reflector được gán cố định là `172.30.0.30` (theo cấu hình trong `docker-compose.yml`).

---

## 3. Quy trình Khởi chạy trên Từng Máy

```
                 Mạng Wi-Fi chung (Hotspot 4G cá nhân)
        ┌─────────────────────────┬─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   Máy Nạn nhân    │     │  Máy Tấn công 1   │     │  Máy Tấn công 2   │
│   (VICTIM LAPTOP) │     │   (ATTACKER 1)    │     │   (ATTACKER 2)    │
│   192.168.1.100   │     │   192.168.1.50    │     │   192.168.1.51    │
├───────────────────┤     ├───────────────────┤     ├───────────────────┤
│ • Nginx Web (:80) │     │ • DNS Reflector   │     │ • Traffic Console │
│ • detector.py     │     │   container (:53) │     │   Web UI (:4000)  │
│ • SOC Console     │     │ • Traffic Console │     │                   │
│   Web UI (:3000)  │     │   Web UI (:4000)  │     │                   │
└───────────────────┘     └───────────────────┘     └───────────────────┘
```

### 3.1. Máy Nạn nhân (VICTIM) — Kết nối Máy chiếu Báo cáo

Máy bạn đóng vai trò là **Trung tâm giám sát điều hành an ninh mạng (SOC Monitor)** và là mục tiêu phòng thủ:

#### Bước 1: Bật Web Server Nginx (Dịch vụ đích cổng 80)
```bash
# Cách 1: Nginx chạy bằng Docker (nhẹ, nhanh)
docker run -d --name victim_web -p 80:80 nginx:alpine

# Cách 2: Hoặc Nginx cài trực tiếp trên máy Ubuntu/Debian
sudo systemctl start nginx
```

#### Bước 2: Khởi chạy Bộ dò kép & Dashboard SOC Console
```bash
cd ~/dos-ddos-project

# Khởi chạy detector Scapy/ML pipe vào Dashboard Server:
sudo .venv/bin/python3 detection/detector.py \
    --iface wlan0 \
    --victim 192.168.1.100 \
    --pps 40 --syn 25 \
    --ml detection/window_model.joblib \
    --stream | node dashboard/server.js --victim 192.168.1.100
```
*(Lưu ý: Thay `wlan0` bằng tên card Wi-Fi của bạn và thay `192.168.1.100` bằng IP máy bạn).*

#### Bước 3: Chiếu lên màn hình Máy chiếu
- Mở trình duyệt web truy cập: **`http://localhost:3000`**.
- Bấm phím **F11** để hiển thị toàn màn hình.
- Màn hình sẽ hiển thị 11 đồ thị sóng đặc trưng thời gian thực, banner xanh **BENIGN**, thẻ Web Service trạng thái **UP (200) 1ms** và thanh gạt phòng thủ `[🛡️ Phòng thủ: TẮT]`.

---

### 3.2. Hai Máy Tấn công (ATTACKER 1 & ATTACKER 2)

Hai máy này đóng vai trò là các nguồn phát sinh tải thử nghiệm (Traffic Generators):

#### Trên Laptop Attacker 1 (Kiêm DNS Reflector):
```bash
# 1. Khởi chạy container DNS Reflector cổng 53 (chỉ cần chạy 1 lần):
cd ~/dos-ddos-project/dns && docker run -d --name dns_reflector -p 53:53/udp $(docker build -q .)

# 2. Khởi chạy Attacker Traffic Generator Console:
cd ~/dos-ddos-project/attacker_dashboard && node server.js --port 4000
```
Mở trình duyệt: **`http://localhost:4000`**.

#### Trên Laptop Attacker 2:
```bash
cd ~/dos-ddos-project/attacker_dashboard && node server.js --port 4000
```
Mở trình duyệt: **`http://localhost:4000`**.

#### Thao tác cấu hình ban đầu trên Web Console (:4000) của CẢ 2 Attacker:
1. Nhập **Target Victim IP**: `192.168.1.100` | **Port**: `80`.
2. Nhập **DNS Reflector IP**: `192.168.1.50` (IP Wi-Fi của máy Attacker 1).
3. Bấm nút **[🔍 Kiểm tra Kết nối]**:
   - Đèn trạng thái chuyển sang màu xanh: **`🟢 SẴN SÀNG: Ping OK | HTTP 200 OK`**.
   - Báo với máy Victim là hai máy Attacker đã sẵn sàng phát tải!

---

## 4. Kịch bản Trình diễn 4 Pha trước Hội đồng / Thầy Cô (Playbook)

| Pha | Hành động trên 2 máy Attacker | Hiện tượng quan sát trên Màn hình Victim (Máy chiếu) | Ý nghĩa Kỹ thuật / Đánh giá |
|---|---|---|---|
| **Pha 1: Trạng thái Bình thường (Baseline)** | Cả 2 Attacker chưa bấm gì. | • Banner xanh lá: **BENIGN (An toàn &middot; Không có tấn công)**.<br>• 11 đồ thị phẳng lặng (0–10 pps).<br>• Web Service: **UP (200) 1–2ms**.<br>• Thanh trượt phòng thủ ở trạng thái: `[🛡️ Phòng thủ: TẮT]`. | Hệ thống giám sát thụ động nền mạng, ghi nhận độ trễ dịch vụ lý tưởng. |
| **Pha 2: Tấn công DoS đơn nguồn** | **Attacker 1:** Bấm nút `[Kịch bản A: SYN Flood (Direct IP)]`.<br>*(Attacker 2 đứng yên)* | • Banner lập tức đổi sang màu cam: **DoS [SYN Flood (L4)]**.<br>• Cả Rule và AI ML cùng phát hiện DoS (Confidence &ge; 98%).<br>• Đồ thị PPS & SYN/s vọt lên ~500–1000 pps.<br>• **Số nguồn n_src = 1**, Entropy $H(src) \approx 0.00$.<br>• Bảng IP hiển thị rõ IP của Attacker 1.<br>&rarr; *Attacker 1 bấm **[STOP ALL TRAFFIC]** &rarr; Hệ thống hạ nhiệt về BENIGN.* | Chứng minh khả năng phân loại chính xác DoS (1 nguồn tập trung) nhờ chỉ số Entropy $H(src) = 0$. |
| **Pha 3: Tấn công DDoS đa nguồn & DNS Amplification** | **Attacker 1:** Bấm `[Kịch bản B: SYN Spoofed]`.<br>**Attacker 2:** Bấm `[Kịch bản C: HTTP Paced]` hoặc `[Kịch bản DNS: Amplification]`. | • Banner chuyển sang đỏ rực: **DDoS [SYN Flood]** / **[DNS amp]**.<br>• **Số nguồn n_src nhảy vọt lên hàng trăm/nghìn IP**.<br>• **Entropy H(src) tăng vọt > 7.0–8.0 bits**.<br>• Cột đồ thị **DNS/s** vọt lên cao khi có DNS reflection.<br>• Thẻ Web Service: chuyển sang **SLOW** hoặc **ERR / TIMEOUT** do nghẽn mạng! | Minh họa sự khác biệt bản chất giữa DoS và DDoS: phân tán nguồn cao làm vọt Entropy $H(src)$ và khiến dịch vụ web bị nghẽn thực sự. |
| **Pha 4: Bật Phòng thủ Closed-loop IPS (Thao tác Đắt giá Nhất)** | Hai máy Attacker vẫn đang tiếp tục phát tải DDoS mạnh mẽ. | • Ngay trên máy chiếu, bạn dùng chuột **gạt thanh trượt [🛡️ Phòng thủ: BẬT]**.<br>• Nút gạt chuyển sang xanh ngọc, hộp eBPF Mitigation viền xanh rực rỡ.<br>• Số đếm **drop/s nhảy vọt lên hàng nghìn gói/giây** (XDP_DROP drop tại card mạng trước khi gói vào Linux network stack).<br>• Thẻ **Web Service lập tức hồi sinh: UP (200) 1ms** trước mắt Thầy Cô! | Chứng minh năng lực giảm thiểu thiệt hại vượt trội của cơ chế In-Kernel Mitigation (eBPF/XDP Closed-loop IPS). |

---

## 5. Lời khuyên & Điểm Mấu chốt khi Thuyết trình

Khi Hội đồng hoặc Thầy Cô đặt câu hỏi, bạn có thể tự tin trả lời dựa trên các luận điểm sau:

1. **Về chế độ Bật/Tắt phòng thủ:**
   > *"Khi thanh trượt ở trạng thái **TẮT**, hệ thống hoạt động ở chế độ **Detect-Only**. Toàn bộ gói tin được truyền lên userspace để tính toán 10 đặc trưng toán học và cho mô hình AI phân loại đánh giá. Khi gạt sang **BẬT**, hệ thống kích hoạt **Closed-loop IPS**: userspace ra lệnh cho eBPF map ở tầng XDP thực hiện drop gói ngay tại driver card mạng trước khi nhân Linux phải tốn CPU cấp phát `sk_buff`."*

2. **Về khả năng phòng thủ các loại tấn công:**
   > *"Hệ thống phòng thủ bằng cơ chế 2 lớp:*
   > - *Với tấn công đơn nguồn hoặc có địa chỉ cụ thể (Kịch bản A, C, U_dos, DNS): eBPF chặn theo **Per-source Blocklist (có TTL tự mở khóa)**.*
   > - *Với tấn công giả mạo hàng nghìn IP ngẫu nhiên (Kịch bản B, U, I spoofing): eBPF áp dụng **Token-Bucket Rate Limiter theo giao thức** (giới hạn trần SYN, UDP, ICMP), cắt bỏ phần lưu lượng vượt ngưỡng để bảo vệ hàng đợi socket của Web Server."*

3. **Tại sao đồ thị vẫn hiển thị sóng khi đã bật phòng thủ?**
   > *"Chương trình eBPF được thiết kế đếm gói tin trước (`bump counters`), sau đó mới thực hiện lệnh `XDP_DROP`. Nhờ vậy, người quản trị SOC trên Dashboard vẫn quan sát được đúng cường độ sóng tấn công từ bên ngoài, hộp eBPF Mitigation hiển thị số gói drop/giây, trong khi Web Service vẫn duy trì trạng thái xanh UP (200) 1ms mà không bị quá tải."*

---

## 6. Phụ lục: Các Lệnh Terminal Thủ công (Tùy chọn)

Nếu trong buổi báo cáo bạn muốn minh họa trực tiếp bằng dòng lệnh thay vì dùng giao diện Attacker Web Console, bạn có thể chạy các lệnh sau trên terminal máy Attacker:

```bash
# 1. Kịch bản A: L4 TCP SYN Flood (DoS 1 nguồn)
sudo hping3 -S -p 80 -i u2000 192.168.1.100

# 2. Kịch bản B: L4 TCP SYN Flood (DDoS giả mạo IP ngẫu nhiên)
sudo hping3 -S -p 80 --rand-source -i u2000 192.168.1.100

# 3. Kịch bản C: L7 HTTP Flood (Apache Benchmark nhịp độ cao)
ab -k -c 50 -n 30000 http://192.168.1.100/

# 4. Kịch bản U: L3/L4 UDP Flood (Volumetric)
sudo hping3 --udp -p 80 -i u2000 192.168.1.100

# 5. Kịch bản I: L3 ICMP Ping Flood
sudo hping3 --icmp -i u2000 192.168.1.100

# 6. Kịch bản DNS: DNS Amplification (chạy từ thư mục repo)
python3 attacks/dns_amp.py --reflector 192.168.1.50 --victim 192.168.1.100 --rate 300 --duration 30
```
- Dừng khẩn cấp bằng lệnh: `pkill hping3; pkill -f dns_amp.py; pkill -f http_flood.py`.
