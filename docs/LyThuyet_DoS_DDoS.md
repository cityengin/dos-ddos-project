# Tài liệu lý thuyết: Tấn công, phát hiện thời gian thực và phòng thủ DoS/DDoS

> Tài liệu nội bộ nhóm – Đồ án PBL3 (Khoa Công nghệ Thông tin, Đại học Bách khoa – Đại học Đà Nẵng).  
> Mục đích: Cung cấp đầy đủ nền tảng lý thuyết mạng, toán học entropy, giải thuật phát hiện và phòng thủ cho các thành viên trước khi đọc mã nguồn và tham gia bảo vệ đồ án.  
> Bản Word tham khảo: [`TaiLieu_LyThuyet_DoS_DDoS.docx`](TaiLieu_LyThuyet_DoS_DDoS.docx).

> ⚠️ **Tuyên bố trách nhiệm – Chỉ dùng cho mục đích giáo dục & nghiên cứu phòng thủ:**  
> Toàn bộ các công cụ tấn công và thử nghiệm trong đề tài được thiết kế để **chỉ chạy trong môi trường lab cô lập** (lab ảo hóa Docker trên dải mạng riêng `172.30.0.0/24` hoặc mạng WiFi/LAN thử nghiệm nội bộ). Tuyệt đối không sử dụng bất kỳ công cụ nào để nhắm vào máy chủ, thiết bị hoặc hạ tầng mạng thực tế mà không có sự cho phép bằng văn bản.

---

## Mục lục

1. [Giới thiệu đề tài](#1-giới-thiệu-đề-tài)
2. [DoS và DDoS – Khái niệm nền tảng](#2-dos-và-ddos--khái-niệm-nền-tảng)
3. [Các kỹ thuật tấn công (3 Vector chính)](#3-các-kỹ-thuật-tấn-công-3-vector-chính)
   - [3.1. TCP SYN Flood – Tầng giao vận (L4)](#31-tcp-syn-flood--tầng-giao-vận-l4)
   - [3.2. UDP Flood – Tầng mạng & giao vận (L3/L4 Volumetric)](#32-udp-flood--tầng-mạng--giao-vận-l3l4-volumetric)
   - [3.3. HTTP Flood – Tầng ứng dụng (L7)](#33-http-flood--tầng-ứng-dụng-l7)
   - [3.4. Bảng so sánh 3 kỹ thuật tấn công](#34-bảng-so-sánh-3-kỹ-thuật-tấn-công)
4. [Kiến trúc hệ thống thử nghiệm](#4-kiến-trúc-hệ-thống-thử-nghiệm)
   - [4.1. Kiến trúc Multi-Machine (Máy thật qua WiFi / LAN)](#41-kiến-trúc-multi-machine-máy-thật-qua-wifi--lan)
   - [4.2. Kiến trúc ảo hóa Docker (Lab cô lập)](#42-kiến-trúc-ảo-hóa-docker-lab-cô-lập)
5. [Nguyên lý phát hiện & 10 đặc trưng thời gian thực](#5-nguyên-lý-phát-hiện--10-đặc-trưng-thời-gian-thực)
   - [5.1. Mô hình phân tích cửa sổ trượt (Sliding Window)](#51-mô-hình-phân-tích-cửa-sổ-trượt-sliding-window)
   - [5.2. Hệ thống 10 đặc trưng thời gian thực](#52-hệ-thống-10-đặc-trưng-thời-gian-thực)
   - [5.3. Toán học Entropy Shannon: Nguồn H(src) & Đích H(dport)](#53-toán-học-entropy-shannon-nguồn-hsrc--đích-hdport)
   - [5.4. Giải thuật phân loại DoS vs DDoS](#54-giải-thuật-phân-loại-dos-vs-ddos)
   - [5.5. Cơ chế phân biệt vector tấn công (SYN vs UDP vs HTTP)](#55-cơ-chế-phân-biệt-vector-tấn-công-syn-vs-udp-vs-http)
   - [5.6. Nguyên tắc bắt buộc: Lọc lưu lượng Inbound (`--victim`)](#56-nguyên-tắc-bắt-buộc-lọc-lưu-lượng-inbound---victim)
   - [5.7. Bảng điều khiển phòng thủ (Victim Defense Console)](#57-bảng-điều-khiển-phòng-thủ-victim-defense-console)
6. [Kết quả thực nghiệm & Phân tích các kịch bản](#6-kết-quả-thực-nghiệm--phân-tích-các-kịch-bản)
7. [Ngưỡng thích nghi động (Adaptive Thresholding bằng EWMA & MAD)](#7-ngưỡng-thích-nghi-động-adaptive-thresholding-bằng-ewma--mad)
8. [So sánh với State-of-the-Art & Học máy (Machine Learning)](#8-so-sánh-với-state-of-the-art--học-máy-machine-learning)
   - [8.1. Thử nghiệm trên Benchmark chuẩn CICDDoS2019](#81-thử-nghiệm-trên-benchmark-chuẩn-cicddos2019)
   - [8.2. So sánh bản chất: Đặc trưng mức Luồng (Flow) vs Đặc trưng mức Cửa sổ (Window)](#82-so-sánh-bản-chất-đặc-trưng-mức-luồng-flow-vs-đặc-trưng-mức-cửa-sổ-window)
   - [8.3. Mô hình Học máy trực tiếp trên 10 đặc trưng cửa sổ (Live Window ML)](#83-mô-hình-học-máy-trực-tiếp-trên-10-đặc-trưng-cửa-sổ-live-window-ml)
9. [Phòng thủ trong nhân Linux: Closed-Loop eBPF/XDP Drop](#9-phòng-thủ-trong-nhân-linux-closed-loop-ebpfxdp-drop)
10. [Cường độ tối đa & Khả năng chịu tải thực tế của dịch vụ](#10-cường-độ-tối-đa--khả-năng-chịu-tải-thực-tế-của-dịch-vụ)
11. [Giới hạn kỹ thuật & Hướng phát triển](#11-giới-hạn-kỹ-thuật--hướng-phát-triển)
12. [Bảng tra cứu thuật ngữ nhanh](#12-bảng-tra-cứu-thuật-ngữ-nhanh)

---

## 1. Giới thiệu đề tài

Đề tài tập trung giải quyết trọn vẹn chu trình an toàn thông tin đối với các cuộc tấn công từ chối dịch vụ:
1. **Mô phỏng tấn công (Attack Simulation):** Xây dựng các kịch bản tấn công thực tế bao gồm **L4 SYN Flood**, **L3/L4 UDP Flood** và **L7 HTTP Flood**, hỗ trợ kỹ thuật giả mạo địa chỉ IP nguồn (IP spoofing).
2. **Trích xuất đặc trưng & Phát hiện thời gian thực (Real-Time Detection):** Thu thập gói tin trực tiếp, trích xuất **10 đặc trưng thống kê** trong mỗi cửa sổ trượt 1 giây, tính toán **Entropy Shannon** đa chiều để nhận diện sự phân tán và phân loại chính xác giữa **DoS** (đơn nguồn) và **DDoS** (đa nguồn / phân tán).
3. **Phòng thủ & Giảm thiểu trong nhân (Kernel-level Mitigation):** Tận dụng công nghệ **eBPF/XDP** để đếm gói ở tốc độ dây (line-rate) và kích hoạt cơ chế tự động chặn lọc gói tin độc hại (`XDP_DROP`) với bộ đếm TTL linh hoạt.
4. **Giám sát trực quan (Victim Defense Console):** Cung cấp giao diện web hiện đại dành riêng cho máy nạn nhân (Victim), hiển thị trực quan 9 đồ thị tham số động, bảng xếp hạng IP tấn công kèm cảnh báo giả mạo, nhật ký sự kiện an ninh và trạng thái khả dụng của dịch vụ.

Hệ thống được thiết kế để triển khai linh hoạt trên **cả hai môi trường**: môi trường **máy vật lý thật (Multi-Machine qua WiFi/LAN)** và môi trường **ảo hóa (Docker Compose)**.

---

## 2. DoS và DDoS – Khái niệm nền tảng

- **DoS (Denial of Service – Từ chối dịch vụ):** Kỹ thuật tấn công nhằm làm cạn kiệt tài nguyên của hệ thống mục tiêu (băng thông mạng, bộ nhớ RAM, CPU, hoặc bảng quản lý kết nối của hệ điều hành), khiến người dùng hợp lệ không thể tiếp cận dịch vụ. DoS xuất phát từ **một nguồn duy nhất**.
- **DDoS (Distributed Denial of Service – Từ chối dịch vụ phân tán):** Cuộc tấn công có cùng mục tiêu như DoS nhưng được điều phối đồng thời từ **nhiều nguồn phân tán** (mạng máy tính ma - botnet, hoặc sử dụng kỹ thuật IP spoofing ngẫu nhiên). Lưu lượng tổng hợp lớn hơn rất nhiều lần và việc ngăn chặn phức tạp hơn do không thể chỉ chặn một địa chỉ IP duy nhất.

### Bảng so sánh tổng quan giữa DoS và DDoS

| Tiêu chí | DoS (Từ chối dịch vụ) | DDoS (Từ chối dịch vụ phân tán) |
|---|---|---|
| **Số lượng nguồn gửi** | Duy nhất 1 máy / 1 địa chỉ IP nguồn thực | Nhiều máy (Botnet) hoặc hàng nghìn IP giả mạo |
| **Cường độ lưu lượng** | Bị giới hạn bởi băng thông/phần cứng của 1 máy | Được cộng dồn từ nhiều nguồn, dễ làm tê liệt hạ tầng |
| **Đặc trưng phân tán** | $n\_src = 1$, Entropy nguồn $H(src) \approx 0.00$ | $n\_src \ge 2$, Entropy nguồn $H(src) \gg 0.00$ |
| **Độ khó khi ngăn chặn** | Đơn giản: Khóa (Blacklist/Drop) IP của nguồn đó | Phức tạp: Phải phân tích hành vi, dùng Token Bucket hoặc Scrubbing |
| **Kịch bản trong Lab** | Kịch bản A (1 nguồn SYN) | Kịch bản B (SYN spoofing), Kịch bản C (HTTP 6 nguồn) |

---

## 3. Các kỹ thuật tấn công (các vector chính)

Dự án hiện thực và phân tích 3 vector tấn công tiêu biểu trải rộng từ tầng mạng/giao vận đến tầng ứng dụng:

```
               Mô hình các tầng tấn công trong đề tài:
┌─────────────────────────────────────────────────────────────┐
│ Tầng 7 - Ứng dụng (L7 Application):   HTTP Flood (GET)     │
├─────────────────────────────────────────────────────────────┤
│ Tầng 4 - Giao vận (L4 Transport):      TCP SYN Flood        │
├─────────────────────────────────────────────────────────────┤
│ Tầng 3/4 - Mạng & Giao vận (L3/L4):    UDP Flood            │
└─────────────────────────────────────────────────────────────┘
```

### 3.1. TCP SYN Flood – Tầng giao vận (L4)

Giao thức TCP thiết lập kết nối tin cậy thông qua cơ chế **bắt tay 3 bước (3-Way Handshake)**:
1. Client gửi cờ `SYN` (Synchronize) yêu cầu kết nối.
2. Server phản hồi cờ `SYN-ACK` (Synchronize-Acknowledge) và dành sẵn một ô nhớ trong hàng đợi **SYN Backlog (Half-Open Queue)**.
3. Client phản hồi cờ `ACK` (Acknowledge) để hoàn tất kết nối và chuyển sang trạng thái `ESTABLISHED`.

```
Quá trình bắt tay 3 bước chuẩn:          Tấn công SYN Flood:
Client               Server             Attacker             Server
  │                    │                   │                   │
  │────── SYN ────────>│                   │────── SYN 1 ─────>│ (Ghi nhận Half-Open 1)
  │<──── SYN-ACK ──────│                   │────── SYN 2 ─────>│ (Ghi nhận Half-Open 2)
  │────── ACK ────────>│ (Established)    │────── SYN 3 ─────>│ (Ghi nhận Half-Open 3)
  │                    │                   │   (Bỏ rơi,        │ ... Hàng đợi đầy!
                                           │    không gửi ACK) │ Từ chối client mới!
```

**Cơ chế tấn công:**
Kẻ tấn công (sử dụng công cụ chuyên dụng `hping3 -S`) liên tục bơm hàng ngàn gói tin mang cờ `SYN` với tốc độ cao nhưng **cố tình không gửi gói ACK cuối cùng**. Máy chủ phải duy trì các kết nối nửa mở (half-open) cho đến khi hết hạn thời gian chờ (timeout). Khi hàng đợi SYN Backlog bị lấp đầy, máy chủ từ chối mọi yêu cầu kết nối TCP mới từ các client hợp lệ.

**Kỹ thuật IP Spoofing trong SYN Flood:**  
Vì giao thức IP ở tầng 3 không có cơ chế xác thực nguồn gửi mặc định, kẻ tấn công có thể sinh ngẫu nhiên địa chỉ IP nguồn trong header IP (cờ `--rand-source` trong `hping3`). Khi đó:
- Gói `SYN-ACK` của server phản hồi sẽ gửi đến các địa chỉ không tồn tại hoặc các máy vô can.
- Phía victim thấy các gói SYN dường như đến từ hàng nghìn nguồn khác nhau, biến một máy tấn công đơn lẻ thành lưu lượng phân tán tương đương botnet.
- **Dấu hiệu nhận biết:** `syn_s` tăng vọt, `ack_s ≈ 0`, tỷ lệ `syn_ratio ≈ 1.0`, `ack_syn_ratio ≈ 0.0`.

### 3.2. UDP Flood – Tầng mạng & giao vận (L3/L4 Volumetric)

Giao thức UDP (User Datagram Protocol) là giao thức **phi kết nối (Connectionless)**, không có cơ chế bắt tay và không cần xác nhận nhận gói tin.

**Cơ chế tấn công:**
Kẻ tấn công (sử dụng công cụ `hping3 --udp`) gửi dồn dập một lượng cực lớn các gói tin UDP datagram tới các cổng ngẫu nhiên hoặc cổng dịch vụ của nạn nhân:
- Khi nhận được gói UDP tới một cổng không có ứng dụng lắng nghe, hệ điều hành của victim phải phân tích header gói tin, xác định không có tiến trình tiếp nhận, và sinh gói tin `ICMP Destination Unreachable (Port Unreachable)` trả về.
- Quá trình này tiêu tốn băng thông truyền dẫn của card mạng (Network Interface Card) và làm cạn kiệt tài nguyên xử lý ngắt (softirq) của CPU victim.
- Giống như SYN flood, UDP không yêu cầu bắt tay nên kẻ tấn công có thể **giả mạo địa chỉ IP nguồn (IP spoofing)** hoàn toàn tự do.
- **Dấu hiệu nhận biết:** `udp_s` tăng cao đột biến và chiếm phần lớn `pps` (`udp_s > syn_s`), trong khi `syn_s` và `ack_s` ở mức thấp.

### 3.3. HTTP Flood – Tầng ứng dụng (L7)

Tấn công từ chối dịch vụ tầng ứng dụng khai thác trực tiếp tài nguyên xử lý của máy chủ web (như Nginx, Apache) và tầng ứng dụng phía sau (PHP, Node.js, Python, Database).

**Cơ chế tấn công:**
Sử dụng công cụ Apache Benchmark (`ab -k`) thiết lập các kết nối TCP **hoàn chỉnh** (đầy đủ bắt tay 3 bước `SYN -> SYN-ACK -> ACK`) và gửi dồn dập các yêu cầu HTTP `GET /` hợp lệ:
- Mỗi yêu cầu hợp lệ buộc Web Server phải cấp phát bộ đệm, đọc file từ đĩa, thực thi xử lý header và ghi log truy cập.
- Làm cạn kiệt giới hạn số lượng tiến trình/luồng phục vụ đồng thời (`worker_connections`, `max_children`) của web server.
- **Tại sao HTTP Flood không thể giả mạo IP (Spoofing)?**  
  Để gửi được yêu cầu HTTP GET, client **bắt buộc phải nhận được gói `SYN-ACK` từ server** để hoàn thành bắt tay TCP. Nếu kẻ tấn công giả mạo IP nguồn, gói `SYN-ACK` sẽ gửi về IP giả đó, máy tấn công không nhận được `SYN-ACK` nên không thể hoàn thành bắt tay và không bao giờ gửi được bản tin HTTP GET. Do đó, lưu lượng HTTP flood luôn phản ánh **địa chỉ IP thật của máy tấn công**.
- **Dấu hiệu nhận biết:** `pps` cao, số lượng gói tin `ack_s` rất lớn do các luồng trao đổi dữ liệu TCP hoàn chỉnh (`ack_s ≫ syn_s`), tỷ lệ `ack_syn_ratio ≫ 1.0`.

### 3.4. DNS Amplification – Tấn công phản xạ & khuếch đại (Reflection/Amplification)

Đây là biến thể volumetric tinh vi, dựa trên hai tính chất: **phản xạ (reflection)** qua máy chủ trung gian và **khuếch đại (amplification)** kích thước phản hồi.

**Cơ chế tấn công:**
- Kẻ tấn công gửi các truy vấn DNS **rất nhỏ** (~40 byte, kèm **EDNS0** quảng cáo bộ đệm UDP lớn) tới một **DNS resolver** (máy phản xạ), nhưng **giả mạo địa chỉ IP nguồn = IP của victim**.
- Resolver tưởng victim là bên hỏi nên gửi **phản hồi rất lớn** (bản ghi TXT/ANY/DNSSEC, ~2.5 KB) **về victim**. Hệ số khuếch đại đo được trong lab ~**40–50×** (một truy vấn ~40 byte sinh ra phản hồi hàng KB).
- Victim bị dội bởi **phản hồi DNS (UDP source port 53)** từ (các) resolver — *không phải* từ kẻ tấn công. Kẻ tấn công ẩn mình và chỉ tốn một phần băng thông rất nhỏ.
- **Điều kiện khuếch đại:** resolver phải gửi được phản hồi UDP lớn — cần EDNS0 (bộ đệm lớn) **và** cấu hình `max-udp-size` lớn; nếu không, phản hồi bị cắt (cờ TC=1) và client phải thử lại qua TCP (không còn khuếch đại). Đây chính là cấu hình sai (open/misconfigured resolver) mà tấn công thực tế lạm dụng.
- **Dấu hiệu nhận biết:** `dns_s` cao (gói UDP source-port 53); khi `dns_s` vượt ngưỡng và áp đảo → gắn nhãn `[DNS amp]`. Số IP nguồn tại victim = số resolver **thật** (thường ít) → nếu chỉ 1 reflector thì phân loại **DoS**.

### 3.5. Bảng so sánh các kỹ thuật tấn công

| Tiêu chí so sánh | TCP SYN Flood | UDP Flood | HTTP Flood | DNS Amplification |
|---|---|---|---|---|
| **Tầng giao thức** | Tầng 4 (TCP) | Tầng 3/4 (UDP) | Tầng 7 (HTTP) | Tầng 3/4 (phản xạ UDP/53) |
| **Bản chất giao thức** | Hướng kết nối | Phi kết nối | Ứng dụng trên nền TCP | Phản xạ + khuếch đại qua resolver |
| **Trạng thái bắt tay** | Bỏ dở (chỉ gửi SYN) | Không có | Hoàn tất 3 bước | Không (query/response UDP) |
| **Tài nguyên bị chiếm dụng** | Hàng đợi SYN Backlog | Băng thông, CPU xử lý ngắt | Worker threads, RAM, Socket | Băng thông (phản hồi khuếch đại) |
| **Khả năng Spoof IP** | **Có thể** | **Có thể** | **Không thể** (IP thật) | **Bắt buộc** (spoof = IP victim) |
| **Đặc trưng thống kê cốt lõi** | `syn_s` cao, `ack_s ≈ 0` | `udp_s` cao, chiếm đa số `pps` | `pps` cao, `ack_s ≫ syn_s` | `dns_s` cao (UDP sport 53), khuếch đại ~40× |

---

## 4. Kiến trúc hệ thống thử nghiệm

Dự án hỗ trợ 2 mô hình triển khai thực nghiệm độc lập:

### 4.1. Kiến trúc Multi-Machine (Máy thật qua WiFi / LAN)

Mô hình này kiểm chứng tính thực tế của giải pháp trên các thiết bị phần cứng thật khi kết nối chung một mạng không dây (WiFi) hoặc switch có dây:

```
                    Mạng WiFi / LAN Thử Nghiệm (DHCP, ví dụ 192.168.1.0/24)
          ┌───────────────────────────────────┬───────────────────────────────────┐
          │                                   │                                   │
┌─────────▼─────────────────────────┐  ┌──────▼────────────────────────┐   ┌──────▼────────────────────────┐
│      LAPTOP NẠN NHÂN (VICTIM)     │  │       MÁY TẤN CÔNG 1          │   │       MÁY TẤN CÔNG 2          │
│                                   │  │        (ATTACKER 1)           │   │        (ATTACKER 2)           │
│ • IP: 192.168.1.50 (wlan0)        │  │ • IP: 192.168.1.61            │   │ • IP: 192.168.1.62            │
│ • Nginx Web Server (Port 80)      │  │ • hping3 (SYN, UDP, ICMP)     │   │ • hping3 (SYN, UDP, ICMP)     │
│ • Bộ phát hiện: detector.py       │  │ • ab (HTTP Flood L7)          │   │ • ab (HTTP Flood L7)          │
│ • Victim Defense Console (Port 3000)│ │ • Phối hợp qua SSH / tay      │   │ • Phối hợp qua SSH / tay      │
└───────────────────────────────────┘  └───────────────────────────────┘   └───────────────────────────────┘
```

- **Victim Laptop:** Đóng vai trò máy chủ cung cấp dịch vụ web tĩnh Nginx tại cổng 80. Chạy tiến trình phát hiện `detector.py` lắng nghe trên card mạng WiFi (`--iface wlan0`) và cung cấp giao diện phòng thủ trực quan tại cổng 3000.
- **Attacker 1 & 2 Laptops:** Chạy độc lập hoặc phối hợp thông qua script điều khiển từ xa qua SSH [`run_ddos_remote.sh`](../run_ddos_remote.sh). Với 2 máy tấn công vật lý, kịch bản HTTP flood tạo ra một cuộc tấn công DDoS L7 phân tán thực sự từ 2 địa chỉ IP khác nhau (`n_src = 2`) mà không cần giả lập.
- Hướng dẫn cấu hình chi tiết: xem [`docs/MULTI_MACHINE.md`](../docs/MULTI_MACHINE.md).

### 4.2. Kiến trúc ảo hóa Docker (Lab cô lập)

Dành cho việc kiểm thử tự động, chạy các kịch bản chuẩn (A..E) và đảm bảo khả năng tái lập kết quả:

```
                          Cầu nối mạng ảo hóa Docker: dos-lab (172.30.0.0/24)
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                        │
  │  ┌────────────────────────┐      ┌────────────────────────┐     ┌───────────────────┐  │
  │  │ victim (172.30.0.10)   │      │ detector (netns victim)│     │ attacker1 (.21)   │  │
  │  │ • nginx:alpine         │◄────►│ • eBPF XDP + detector  │◄────┤ • hping3, ab      │  │
  │  │ • export host:8080     │      │ • scikit-learn / joblib│     │ attacker2..6 (.26)│  │
  │  └────────────────────────┘      └────────────────────────┘     └───────────────────┘  │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

- Sử dụng `network_mode: service:victim` cho container detector, cho phép detector chia sẻ không gian tên mạng (network namespace) với victim, quan sát chính xác từng gói tin đi vào card mạng `eth0` của victim.

---

## 5. Nguyên lý phát hiện & 10 đặc trưng thời gian thực

### 5.1. Mô hình phân tích cửa sổ trượt (Sliding Window)

Detector thu thập lưu lượng và cập nhật trạng thái theo chu kỳ đều đặn **1 giây** (`--interval 1.0`). Toàn bộ gói tin đến trong 1 giây được tổng hợp, tính toán đặc trưng thống kê, so sánh ngưỡng và đưa ra phán quyết.

Hệ thống hỗ trợ 2 backend thu thập:
1. **Scapy Backend (Userspace):** Đơn giản, chạy trực tiếp trên socket mạng người dùng. Phù hợp cho mạng WiFi và tốc độ gói tin vừa phải (< 5,000 pps).
2. **eBPF/XDP Backend (In-Kernel):** Gắn chương trình đếm trực tiếp vào tầng driver mạng của nhân Linux. Đếm chính xác ở tốc độ dây (line-rate > 100,000 pps) mà không gây rớt gói tin.

### 5.2. Hệ thống 10 đặc trưng thời gian thực

Hệ thống trích xuất và giám sát liên tục **10 đặc trưng thời gian thực**:

| STT | Tên đặc trưng | Đơn vị | Định nghĩa & Ý nghĩa toán học | Vai trò trong phân loại an ninh |
|:---:|---|:---:|---|---|
| **1** | `pps` | gói/giây | Tổng số gói tin hợp lệ đi vào victim trong cửa sổ 1 giây. | Đo cường độ lưu lượng tổng thể; kích hoạt cảnh báo khi vượt ngưỡng. |
| **2** | `syn_s` | gói/giây | Số lượng gói TCP có cờ `SYN` bật trong 1 giây. | Dấu hiệu nhận diện chính của tấn công TCP SYN Flood. |
| **3** | `ack_s` | gói/giây | Số lượng gói TCP có cờ `ACK` bật trong 1 giây. | Thước đo kết nối hoàn tất; phân biệt giữa L4 (ACK thấp) và L7 (ACK cao). |
| **4** | `udp_s` | gói/giây | Số lượng gói UDP datagram nhận được trong 1 giây. | Xác định cuộc tấn công thể tích UDP Flood. |
| **5** | `h_src` | bit | Entropy Shannon tính trên phân bố địa chỉ IP nguồn: $H(src) = -\sum p_i \log_2(p_i)$ | Đo mức độ phân tán nguồn: xấp xỉ 0 (1 nguồn), tăng cao khi có nhiều nguồn/spoofing. |
| **6** | `h_dport` | bit | Entropy Shannon tính trên phân bố cổng đích: $H(dport) = -\sum p_j \log_2(p_j)$ | Phân biệt tấn công nhắm vào 1 cổng dịch vụ ($H \approx 0$) hay quét cổng diện rộng. |
| **7** | `n_src` | số lượng | Số lượng địa chỉ IP nguồn duy nhất quan sát được trong 1 giây. | Thước đo phân tán cốt lõi; kết hợp với độ "áp đảo" của nguồn lớn nhất để quyết định DoS vs DDoS. |
| **8** | `syn_ratio` | tỷ lệ | Tỷ số giữa số gói SYN và tổng số gói tin: $\frac{syn\_s}{\max(pps, 1.0)}$ | Tiến tới $1.0$ khi bị tấn công SYN Flood thuần túy; rất thấp trong HTTP/UDP. |
| **9** | `ack_syn_ratio`| tỷ lệ | Tỷ số giữa số gói ACK và số gói SYN: $\frac{ack\_s}{\max(syn\_s, 1.0)}$ | Rất lớn trong kết nối HTTP hoàn chỉnh ($ack \gg syn$); xấp xỉ 0 trong SYN Flood. |
| **10** | `rate_per_src` | gói/giây/nguồn | Tốc độ gói trung bình trên mỗi nguồn: $\frac{pps}{\max(n\_src, 1)}$ | Tách **flash crowd** (nhiều nguồn, per-nguồn THẤP) khỏi **HTTP-DDoS** (nhiều nguồn, per-nguồn CAO). |

### 5.3. Toán học Entropy Shannon: Nguồn H(src) & Đích H(dport)

Entropy thông tin của Claude Shannon đo lường mức độ **hỗn loạn hoặc phân tán** của một phân bố xác suất:

$$H(X) = - \sum_{i=1}^{k} p_i \log_2(p_i)$$

Trong đó $p_i = \frac{c_i}{N}$ là tỷ lệ gói tin thuộc về đối tượng thứ $i$ trên tổng số $N$ gói tin trong cửa sổ.

#### Ý nghĩa của Entropy nguồn $H(src)$:
- **Trường hợp 1 nguồn (DoS):** Tất cả gói tin đều đến từ một IP duy nhất ($k = 1, p_1 = 1$). Khi đó:
  $$H(src) = - (1 \cdot \log_2(1)) = 0.00 \text{ bit}$$
- **Trường hợp 6 nguồn phân bố đều (kịch bản DDoS HTTP):** Mỗi nguồn chiếm $p_i = 1/6$. Khi đó:
  $$H(src) = - 6 \cdot \left(\frac{1}{6} \log_2\frac{1}{6}\right) = \log_2(6) \approx 2.58 \text{ bit}$$
- **Trường hợp IP Spoofing ngẫu nhiên (kịch bản DDoS SYN):** Hàng nghìn địa chỉ IP ngẫu nhiên xuất hiện trong 1 giây. Entropy tăng vọt lên:
  $$H(src) \approx \log_2(2300) \approx 11.17 \text{ bit}$$

#### Ý nghĩa của Entropy cổng đích $H(dport)$:
- Khi kẻ tấn công tập trung đánh vào web server (cổng 80 duy nhất): $H(dport) \approx 0.00$.
- Khi kẻ tấn công thực hiện Port Scanning hoặc UDP Flood rải rác trên toàn bộ dải cổng: $H(dport)$ tăng cao, phản ánh sự phân tán cổng đích.

### 5.4. Giải thuật phân loại DoS vs DDoS

Quy trình phân loại thực hiện theo các bước tuần tự:
1. **Kiểm tra ngưỡng kích hoạt (Trigger):** Cảnh báo được kích hoạt khi `pps ≥ --pps` HOẶC `syn_s ≥ --syn`.
2. **Xác định phạm vi nguồn (số nguồn + độ áp đảo — bền với nhiễu nền trên mạng chia sẻ):**
   - **DDoS** khi $n\_src \ge$ `--ddos-min-src` (mặc định 10 — rất nhiều nguồn: spoof hoặc nhiều máy) **hoặc** ($n\_src \ge 2$ **và** tỷ lệ gói của nguồn lớn nhất `top_share` $<$ `--ddos-dom-share`, mặc định 0.8 — không nguồn nào áp đảo).
   - **DoS** còn lại (một nguồn áp đảo, `top_share` $\approx 1.0$, $H(src) \approx 0$) — kể cả khi vài gói nền đẩy $n\_src$ vượt 1.

### 5.5. Cơ chế phân biệt vector tấn công (SYN vs UDP vs HTTP)

Sau khi xác định có tấn công, detector phân tích tương quan giữa các cờ và giao thức để gắn thẻ loại tấn công:
- **Thẻ `[SYN flood]`:** Kích hoạt khi `syn_s >= ngưỡng` VÀ `ack_s < syn_s * 0.2` (đặc trưng kết nối nửa mở, thiếu ACK phản hồi).
- **Thẻ `[UDP flood]`:** Kích hoạt khi `udp_s >= --pps` VÀ `udp_s > syn_s` (gói tin UDP áp đảo hoàn toàn lưu lượng vào).
- **Nhận diện HTTP flood (L7):** Lưu lượng có `pps` cao, `ack_s` rất cao ($ack\_s \gg syn\_s$), tỷ lệ `ack_syn_ratio` lớn, phản ánh các phiên trao đổi dữ liệu TCP hoàn tất.

### 5.6. Nguyên tắc bắt buộc: Lọc lưu lượng Inbound (`--victim`)

Khi detector chạy trên máy victim hoặc dùng chung namespace mạng với victim, card mạng sẽ ghi nhận **cả 2 chiều lưu lượng**:
- Chiều gói tin từ ngoài gửi tới victim (Inbound).
- Chiều gói tin victim tự phản hồi ra ngoài (Outbound, ví dụ gói `SYN-ACK` hoặc trả lời HTTP).

> [!IMPORTANT]
> Nếu không lọc bỏ gói tin victim tự gửi đi, gói phản hồi `SYN-ACK` (có IP nguồn là chính victim) sẽ bị detector tính thành một nguồn thứ 2. Hậu quả: cuộc tấn công DoS 1 nguồn sẽ bị **nhận định sai thành DDoS** ($n\_src = 2$), và số lượng `ack` bị thổi phồng làm mất dấu hiệu của SYN flood.  
> **Giải pháp:** Detector bắt buộc áp dụng bộ lọc `--victim <IP_VICTIM>`, chỉ đếm các gói tin có địa chỉ IP đích trùng với IP victim (`pkt[IP].dst == VICTIM`).

### 5.7. Bảng điều khiển phòng thủ (Victim Defense Console)

Phần mềm bảng điều khiển ([`dashboard/`](../dashboard/)) được thiết kế lại toàn diện thành một giao diện phòng thủ chuyên dụng (Defense Console) chạy trực tiếp trên máy nạn nhân:
- **Kiến trúc luồng dữ liệu:** Nhận dữ liệu thời gian thực từ detector qua đường ống tiêu chuẩn (pipe `detector.py --stream | node server.js`) hoặc qua giao diện lập trình ứng dụng REST (`POST /api/metric`), truyền phát tới trình duyệt qua kết nối WebSocket.
- **Biểu đồ trượt 10 đặc trưng:** Sử dụng canvas tối ưu để vẽ liên tục 10 biểu đồ sparkline trượt trong 60 giây, giúp người quản trị quan sát tức thời biến thiên của `pps`, `syn_s`, `ack_s`, `udp_s`, `h_src`, `h_dport`, `n_src`, `syn_ratio`, `ack_syn_ratio`, và `rate_per_src`.
- **Bảng Top Attacker IPs:** Liệt kê các địa chỉ IP gửi nhiều gói tin nhất trong mỗi giây, tính toán tỷ lệ phần trăm đóng góp lưu lượng, và tự động gắn cờ cảnh báo **SPOOFED IP** khi phát hiện địa chỉ nguồn thuộc các dải ngẫu nhiên.
- **Nhật ký sự kiện (Event Log):** Ghi nhận có thứ tự thời gian các sự kiện an ninh mạng theo từng cấp độ (`safe`, `warn`, `crit`, `info`).
- **Thăm dò sức khỏe dịch vụ (Service Health):** Liên tục gửi HTTP probe tới web server Nginx mỗi 3 giây để đo độ trễ đáp ứng (latency tính bằng mili-giây) và mã phản hồi HTTP 200, phản ánh chính xác trạng thái "sống/chết" của website.

---

## 6. Kết quả thực nghiệm & Phân tích các kịch bản

Bảng tổng hợp dữ liệu thực nghiệm được đo đạc trực tiếp trong hệ thống lab:

| Kịch bản | Mô tả chi tiết | pps | syn/s | ack/s | udp/s | n_src | H(src) | Phán quyết của Detector | Thời gian phát hiện |
|---|---|---|---|---|---|---|---|---|---|
| **A** | DoS 1 nguồn (SYN flood, IP thật) | ~300 | ~150 | 0 | 0 | **1** | **0.00** | **DoS `[SYN flood]`** | < 1 giây |
| **B** | DDoS SYN flood (Giả mạo IP spoofing) | ~4000 | ~2000 | 0 | 0 | **~2300** | **~11.1** | **DDoS `[SYN flood]`** | < 1 giây |
| **C** | DDoS HTTP flood (6 nguồn máy thật) | ~1800 | ~400 | ~1400 | 0 | **6** | **~2.58** | **DDoS** (L7) | < 1 giây |
| **D** | Tấn công SYN tốc độ thấp dưới ngưỡng | ~24 | ~12 | 0 | 0 | ~20 | ~4.2 | Bị luật bỏ sót; **ML bắt được** | < 1 giây |
| **E** | Flash crowd hợp lệ (Truy cập tăng cao) | ~350 | ~70 | ~280 | 0 | 1 | 0.00 | Luật báo nhầm; **ML phân loại BENIGN** | N/A |

### Phân tích đồ thị diễn biến:
- Trong kịch bản A và B, đồ thị `ack_s` duy trì ở mức 0 tuyệt đối, trong khi `syn_s` tăng tương ứng với cường độ phát gói tin.
- Ở kịch bản B, do kích hoạt tính năng `--spoof`, mỗi gói tin mang một IP nguồn ngẫu nhiên, dẫn đến số lượng nguồn $n\_src$ và entropy $H(src)$ tăng vọt tương đương với một cuộc tấn công phân tán từ botnet quy mô lớn.
- Trong kịch bản C, đường biểu diễn `ack_s` vượt trội so với `syn_s`, minh chứng cho việc các luồng HTTP GET đã hoàn tất bắt tay TCP thành công.

---

## 7. Ngưỡng thích nghi động (Adaptive Thresholding bằng EWMA & MAD)

Ngưỡng cố định (ví dụ `pps >= 40`, `syn >= 25`) có nhược điểm chí mạng trong thực tế:
- Đặt ngưỡng quá thấp $\implies$ Báo động giả khi có lưu lượng hợp lệ tăng nhẹ (giờ cao điểm).
- Đặt ngưỡng quá cao $\implies$ Bỏ sót các cuộc tấn công tinh vi tốc độ thấp (Low-rate DoS).

### Thuật toán ngưỡng thích nghi trong dự án:
Detector tích hợp giải thuật cập nhật ngưỡng tự động dựa trên **Trung bình trượt có trọng số mũ (EWMA)** và **Độ lệch tuyệt đối trung vị (MAD)**:

$$\mu_{t} = \alpha \cdot x_t + (1 - \alpha) \cdot \mu_{t-1}$$
$$\text{MAD}_{t} = \alpha \cdot |x_t - \mu_{t-1}| + (1 - \alpha) \cdot \text{MAD}_{t-1}$$
$$\text{Ngưỡng}_t = \max\left( \mu_t + k \cdot \text{MAD}_t, \text{Sàn tối thiểu} \right)$$

- $\alpha$ (hệ số làm mịn, mặc định 0.2): kiểm soát tốc độ học đường cơ sở (baseline).
- $k$ (hệ số độ nhạy, mặc định 4.0): xác định khoảng cách lệch chuẩn cho phép trước khi cảnh báo.
- **Cơ chế chống nhiễm độc Baseline:** Hệ thống **chỉ cập nhật $\mu$ và MAD trong các cửa sổ KHÔNG có cảnh báo**. Khi phát hiện tấn công, quá trình học lập tức đóng băng để tránh việc lưu lượng tấn công làm biến dạng đường cơ sở.

---

## 8. So sánh với State-of-the-Art & Học máy (Machine Learning)

### 8.1. Thử nghiệm trên Benchmark chuẩn CICDDoS2019

Để đối chứng giải thuật luật ngưỡng với nghiên cứu quốc tế, nhóm tiến hành huấn luyện các mô hình học máy trên bộ dữ liệu **CICDDoS2019** (công bố bởi Viện An ninh mạng Canada - University of New Brunswick):
- Bộ dữ liệu gồm hơn 131,000 luồng kết nối đã làm sạch, 63 đặc trưng số học và 13 họ tấn công khác nhau (NTP, DNS, LDAP, MSSQL, NetBIOS, SNMP, Portmap, UDP, SYN, TFTP, WebDDoS...).
- **Kết quả phát hiện nhị phân (Tấn công vs Hợp lệ):**
  - Luật ngưỡng đơn (trên đặc trưng tốc độ tốt nhất): **F1-Score = 0.60**
  - **Random Forest:** **F1-Score = 0.999** (Độ chính xác 99.9%)
  - **HistGradientBoosting:** **F1-Score = 0.996**
- **Kết quả phân loại đa lớp (Nhận diện 13 họ tấn công):** Đạt độ chính xác tổng thể **93.0%**, macro-F1 **0.735**.

### 8.2. So sánh bản chất: Đặc trưng mức Luồng (Flow) vs Đặc trưng mức Cửa sổ (Window)

Đây là điểm khác biệt cốt lõi cần làm rõ khi bảo vệ đề tài:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│              SO SÁNH HAI PHƯƠNG PHÁP TIẾP CẬN DỮ LIỆU ĐẶC TRƯNG                │
├───────────────────────────────────────┬─────────────────────────────────────────┤
│    ĐẶC TRƯNG MỨC LUỒNG (FLOW-LEVEL)   │   ĐẶC TRƯNG MỨC CỬA SỔ (WINDOW-LEVEL)   │
│       (Ví dụ: CICDDoS2019)            │          (Dự án hiện tại)               │
├───────────────────────────────────────┼─────────────────────────────────────────┤
│ • Tính toán trên từng kết nối 5-tuple │ • Tính toán tổng hợp trên toàn bộ card  │
│   (Src IP, Dst IP, Sport, Dport, Proto) mạng trong cửa sổ thời gian cố định (1s)│
│ • Cần quan sát cả chiều đi lẫn chiều  │ • Đếm tức thời gói tin Inbound, không   │
│   về của luồng (Forward & Backward)   │   phụ thuộc vào trạng thái đóng luồng   │
│ • Các đặc trưng: IAT (thời gian giữa  │ • Các đặc trưng: pps, syn_s, ack_s,     │
│   các gói), Min/Max Packet Length...  │   udp_s, syn_ratio, ack_syn_ratio       │
│ • KHÔNG CÓ đặc trưng phân tán toàn    │ • ĐẶC BIỆT CÓ các đặc trưng toàn cục:   │
│   cục (Không có H(src), H(dport),     │   Entropy H(src), Entropy H(dport),     │
│   và số lượng nguồn phân tán n_src)   │   Số nguồn duy nhất n_src               │
│ • Độ trễ: Phải chờ luồng kết thúc     │ • Độ trễ: Cực thấp (< 1 giây), phát hiện│
│   mới trích xuất đủ đặc trưng         │   ngay lập tức theo thời gian thực      │
└───────────────────────────────────────┴─────────────────────────────────────────┘
```

Vì mô hình CICDDoS2019 yêu cầu 63 đặc trưng mức flow (chỉ có được sau khi kết thúc luồng), nó không thể gắn trực tiếp vào vòng lặp phát hiện từng giây của detector mà không gây trễ.

### 8.3. Mô hình Học máy trực tiếp trên 10 đặc trưng cửa sổ (Live Window ML)

Để khắc phục giới hạn trên, đề tài xây dựng pipeline học máy thời gian thực ([`ml/train_window.py`](../ml/train_window.py)):
1. Thu thập dữ liệu: [`experiments/capture_session.py`](../experiments/capture_session.py) chạy ma trận kịch bản trong lab và ghi pcap + timeline; [`ml/pcap_to_windows.py`](../ml/pcap_to_windows.py) trích cửa sổ trượt có nhãn vào [`ml/data/windows_pcap.csv`](../ml/data/windows_pcap.csv) bằng module đặc trưng dùng chung [`detection/window_features.py`](../detection/window_features.py).
2. Huấn luyện mô hình Random Forest trên chính **10 đặc trưng cửa sổ thời gian thực**, đánh giá bằng leave-one-run-out (1 pcap = 1 run).
3. Lưu mô hình vào file [`detection/window_model.joblib`](../detection/window_model.joblib).
4. Tích hợp trực tiếp vào detector qua tham số `--ml`: Mỗi giây, detector trích xuất vector 10 đặc trưng, nạp vào mô hình và đưa ra dự đoán `ml_verdict` song song với phán quyết của luật.

**Hiệu quả giải quyết bài toán biên:**
- **Kịch bản D (SYN spoof tốc độ thấp ~24 pps):** Nằm dưới ngưỡng của luật nên luật bỏ lọt (0% phát hiện). Mô hình ML phát hiện chính xác **100%** nhờ học được sự kết hợp giữa $H(src)$ cao và $ack\_syn\_ratio \approx 0$.
- **Kịch bản E (Flash crowd hợp lệ ~350 pps):** Vượt ngưỡng lưu lượng nên luật báo động sai. Mô hình ML nhận biết tỷ lệ $ack\_syn\_ratio$ cao và $n\_src = 1$, phân loại chính xác là **BENIGN** (hợp lệ).

---

## 9. Phòng thủ trong nhân Linux: Closed-Loop eBPF/XDP Drop

Hệ thống cung cấp cơ chế phòng thủ tự động vòng lặp kín (Closed-Loop Defense) bằng công nghệ **XDP (eXpress Data Path)** chạy trực tiếp trong kernel:

```
                      Quy trình xử lý gói tin tại tầng XDP:
                      
  Gói tin từ mạng ──► [ XDP Ingress Hook ]
                             │
                             ├─► Đếm gói tin vào BPF Maps (packets, syn, ack, src_ip)
                             │
                             ▼
                    Kiểm tra Blocklist?
                    ├── Có ──► [ XDP_DROP ] (Loại bỏ ngay tại driver, 0% tải CPU)
                    │
                    └── Không ─► Token Bucket theo giao thức (SYN/UDP/ICMP)?
                                 ├── Vượt giới hạn ──► [ XDP_DROP ]
                                 └── Bình thường ────► [ XDP_PASS ] ──► Chuyển tiếp tới Nginx
```

1. **Nguyên lý Đếm trước - Chặn sau:** XDP luôn cập nhật bộ đếm trước khi áp dụng hành động thả gói. Nhờ vậy, detector vẫn ghi nhận chính xác cường độ thực của cuộc tấn công trong khi máy chủ không bị quá tải.
2. **Chặn theo nguồn có thời hạn (Per-Source Drop with TTL):** Nguồn IP gửi vượt ngưỡng `--block-pps` (ví dụ 300 gói/s) sẽ bị ghi vào BPF Map `blocklist` kèm mốc thời gian sống TTL (`--block-ttl`, ví dụ 5 giây). Sau 5 giây, mục này tự động hết hạn, tránh chặn vĩnh viễn IP của người dùng.
3. **Token Bucket toàn cục theo giao thức (`--block-syn-rate` / `--block-udp-rate` / `--block-icmp-rate`):** Đối với tấn công giả mạo IP ngẫu nhiên (mỗi gói một IP khác nhau), việc chặn theo từng IP là vô tác dụng. Hệ thống dùng Token Bucket với khóa xoay (`bpf_spin_lock`) trong nhân, giới hạn tổng số gói mỗi giao thức (SYN / UDP / ICMP) không vượt quá $N$ gói/giây. Đo trong lab: `--block-udp-rate 1000` cắt **~90%** UDP flood spoof, `--block-icmp-rate 500` cắt **~95%** ICMP flood spoof. Đánh đổi: một phần lưu lượng hợp lệ cùng giao thức cũng bị rớt khi tổng vượt ngưỡng.
4. **Phòng thủ DNS Amplification (bài học tương phản):** Khác với flood spoof trực tiếp, tại victim một đợt DNS amplification chỉ gồm lưu lượng từ **số ít resolver THẬT** (không giả mạo được, vì phản hồi phải quay về victim). Do đó **chặn theo nguồn (per-source) lại rất hiệu quả**: reflector vượt `--block-pps` sẽ bị đưa vào blocklist và drop — đo trong lab **~100%** phản hồi khuếch đại bị loại bỏ ngay tại XDP. Đây là điểm đối lập thú vị: cùng là volumetric spoof, nhưng SYN/UDP/ICMP spoof cần giới hạn theo tốc độ, còn DNS amp lại trị được bằng chặn nguồn.

---

## 10. Cường độ tối đa & Khả năng chịu tải thực tế của dịch vụ

Khi thử nghiệm đẩy cường độ tấn công lên mức tối đa (Line-rate) bằng các công cụ chuyên dụng như `hping3 --flood` và ApacheBench (`ab -k -c 500`):

| Trạng thái thử nghiệm | Lưu lượng vào victim | Tỷ lệ rớt gói eth0 | Yêu cầu khách hợp lệ | Độ trễ p50 / p95 | Tải CPU Host (20 Cores) |
|---|---|---|---|---|---|
| **Nghỉ (Idle)** | ~28 pps | 0% | 30/30 thành công (100%) | 1 ms / 1 ms | ~0.3 |
| **A-max (SYN 1 nguồn --flood)** | **~190,000 pps** | **0%** | 37/37 thành công (100%) | 1 ms / 1 ms | ~0.9 |
| **B-max (SYN spoof --flood)** | **~123,000 pps** | **0%** | 36/36 thành công (100%) | 0 ms / 1 ms | ~1.7 |
| **C-max (HTTP ab -c 500)** | **~693,000 pps** | **0%** | 35/35 thành công (100%) | 1 ms / **11 ms** | ~3.7 |

### Đánh giá khoa học và khách quan:
- Nhờ cơ chế **SYN Cookies** mặc định trong nhân Linux hiện đại và kiến trúc hướng sự kiện (event-driven) cực nhanh của máy chủ Nginx, hệ thống hấp thụ hoàn hảo các đợt bắn phá mà không làm sập dịch vụ web.
- Khách hàng hợp lệ vẫn đạt **tỷ lệ thành công 100% (HTTP 200 OK)**, tác động rõ ràng nhất là đuôi độ trễ (p95) trong kịch bản HTTP tăng từ 1 ms lên 11 ms.
- Khi kích hoạt tính năng `--block`, chương trình XDP loại bỏ gói tin ngay tại tầng thấp nhất, giảm tải lưu lượng HTTP từ **433,000 pps xuống chỉ còn 28 pps**, khôi phục độ trễ p95 về mức nền 1 ms.

---

## 11. Giới hạn kỹ thuật & Hướng phát triển

### Giới hạn kỹ thuật:
1. **Giả mạo địa chỉ IP (IP Spoofing):** Từ góc nhìn của victim, một máy tấn công đơn lẻ sinh IP giả mạo ngẫu nhiên tạo ra phân bố lưu lượng hoàn toàn giống với một mạng botnet gồm hàng ngàn máy tính thật.
2. **Tấn công tốc độ chậm (Low-and-Slow):** Các cuộc tấn công như Slowloris duy trì kết nối HTTP mở bằng cách gửi từng byte cách nhau khoảng thời gian dài có lưu lượng pps rất nhỏ, dễ dàng vượt qua các ngưỡng thể tích nếu không kết hợp phân tích thời gian giữ kết nối.
3. **Phạm vi bảo vệ Host-based:** Bộ lọc XDP bảo vệ tài nguyên CPU và bộ nhớ của máy chủ, nhưng nếu cuộc tấn công làm nghẽn hoàn toàn đường truyền băng thông vật lý của nhà cung cấp mạng (ISP uplink saturation), việc phòng thủ bắt buộc phải thực hiện ở các tầng mạng phía trên (BGP Flowspec, Cloud Scrubbing Center).

### Hướng phát triển tiếp theo:
- Ứng dụng giải thuật **CUSUM (Cumulative Sum)** đa cửa sổ để phát hiện sớm các biến động nhỏ trong lưu lượng.
- Kết hợp giải thuật phân tích hành vi người dùng (User Behavioral Analysis) để nhận diện các công cụ giả lập trình duyệt tự động trong tấn công L7.
- Mở rộng kiến trúc phòng thủ phối hợp điều khiển mạng qua phần mềm (SDN OpenFlow).

---

## 12. Bảng tra cứu thuật ngữ nhanh

| Thuật ngữ | Tên đầy đủ / Ý nghĩa chi tiết |
|---|---|
| **DoS** | *Denial of Service* – Tấn công từ chối dịch vụ từ một nguồn duy nhất. |
| **DDoS** | *Distributed Denial of Service* – Tấn công từ chối dịch vụ phân tán từ nhiều nguồn. |
| **TCP SYN / ACK** | Các cờ điều khiển (Control Flags) trong quá trình bắt tay 3 bước của giao thức TCP. |
| **Half-Open Connection** | Trạng thái kết nối TCP dở dang khi server đã gửi `SYN-ACK` nhưng chưa nhận được `ACK`. |
| **IP Spoofing** | Kỹ thuật giả mạo địa chỉ IP nguồn trong gói tin IP để che giấu danh tính hoặc giả lập đa nguồn. |
| **pps** | *Packets per second* – Số lượng gói tin truyền nhận trong mỗi giây. |
| **syn_s / ack_s / udp_s** | Số lượng gói tin SYN / ACK / UDP quan sát được trong mỗi giây. |
| **syn_ratio** | Tỷ số giữa số gói tin SYN và tổng số gói tin trong cửa sổ thời gian. |
| **ack_syn_ratio** | Tỷ số giữa số gói tin ACK và số gói tin SYN trong cửa sổ thời gian. |
| **Entropy Shannon $H(src)$** | Thước đo mức độ phân tán của lưu lượng trên các địa chỉ IP nguồn. |
| **Entropy Shannon $H(dport)$**| Thước đo mức độ phân tán của lưu lượng trên các cổng đích. |
| **EWMA & MAD** | *Exponential Weighted Moving Average & Median Absolute Deviation* – Kỹ thuật ước lượng ngưỡng động thích nghi. |
| **eBPF & XDP** | *Extended Berkeley Packet Filter & eXpress Data Path* – Công nghệ xử lý và lọc gói tin siêu tốc trong nhân Linux. |
| **Flow-Level vs Window-Level**| Phân tích theo từng luồng kết nối 5-tuple riêng biệt vs Phân tích tổng hợp theo cửa sổ thời gian trượt. |
| **Victim Defense Console** | Giao diện điều khiển và giám sát an ninh thời gian thực chuyên dụng dành cho máy nạn nhân. |

---
*Đồ án PBL3 — Khoa Công nghệ Thông tin, Trường Đại học Bách khoa – Đại học Đà Nẵng.*
