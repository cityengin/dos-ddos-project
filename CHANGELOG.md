# Nhật ký thay đổi (Changelog)

Mọi thay đổi đáng chú ý của dự án sẽ được ghi nhận chi tiết trong tài liệu này.

Định dạng tài liệu dựa trên tiêu chuẩn [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
và tuân thủ quy tắc đánh số phiên bản [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Chưa phát hành]

### Thay đổi

- **Khôi phục kịch bản HTTP paced phục vụ tập dữ liệu ML và đồng bộ hóa tài liệu theo công cụ hping3/ab.** Quá trình chuyển đổi 100% sang hping3/ab trước đó đã chuyển `capture_session.c_http` sang `ab` (vốn không giới hạn tốc độ yêu cầu), vô tình bỏ qua tham số `pps` và đẩy pha thu thập L7 lên tốc độ line-rate — gây ra hiện tượng lệch phân phối dữ liệu (domain shift). Dự án đã khôi phục `attacks/http_flood.py` (hỗ trợ điều tiết `--pps`) và trỏ `c_http` trở lại kịch bản này (H1 ~150 req/s, D2h ~150/nguồn, D5h ~120/nguồn); công cụ `ab` ở tốc độ line-rate được giữ lại phục vụ riêng cho các kịch bản demo tải tối đa. Đồng bộ hóa toàn bộ tài liệu Markdown (`README.md`, `docs/TESTING.md`, `docs/MULTI_MACHINE.md`, `docs/LyThuyet_DoS_DDoS.md`) khớp với mã nguồn hiện tại: dùng `hping3` cho SYN/UDP/ICMP, `http_flood.py --pps` kết hợp `ab` cho L7, mô hình cửa sổ **10** đặc trưng (bổ sung `rate_per_src`), quy tắc phân loại DoS/DDoS dựa trên số lượng nguồn kết hợp mức độ áp đảo, và quy trình dữ liệu PCAP→LORO.
- **Bộ phân loại DoS và DDoS cải tiến dựa trên số lượng nguồn kết hợp độ áp đảo (Dominance)**, thay vì chỉ xét điều kiện đơn giản `n_src >= 2`. Bổ sung hai cờ `--ddos-min-src` (mặc định 10) và `--ddos-dom-share` (mặc định 0.8): một cửa sổ được xác định là DDoS khi `n_src >= --ddos-min-src` (rất nhiều nguồn do IP spoofing hoặc botnet lớn) HOẶC (`n_src >= 2` VÀ tỷ lệ gói của nguồn lớn nhất `top_share < --ddos-dom-share` — không có nguồn đơn lẻ nào áp đảo); ngược lại được phân loại là DoS. Khắc phục triệt để lỗi phân loại sai trên mạng thực tế: khi kết nối WiFi trường học/công ty, một đòn DoS đơn nguồn thường bắt dính 1–2 gói tin nền ngẫu nhiên đến victim trong mỗi cửa sổ, khiến luật cũ `n_src >= 2` báo nhầm thành DDoS — chỉ số `top_share ≈ 1.0` (và $H(src) \approx 0$) chứng minh đây thực chất là DoS đơn nguồn. Bổ sung trường `top=<share>` trên dòng cảnh báo DoS/DDoS; các định dạng CSV / `--stream` / ML / `--adaptive` / `[SYN flood]` / `[UDP flood]` được giữ nguyên tính tương thích.
- **`detector.py --ml` cung cấp đầy đủ vector 10 đặc trưng**: Bổ sung `udp_s` và `rate_per_src` vào từ điển đặc trưng ML chạy live để khớp hoàn toàn với `window_features.FEATURES`, giúp `--ml` nạp mô hình cửa sổ 10 đặc trưng mà không gặp lỗi `KeyError`, đồng thời vẫn tương thích ngược với mô hình 8 đặc trưng cũ. File nhị phân `detection/window_model.joblib` được huấn luyện lại trên tập dữ liệu PCAP 3 lần chạy (3,362 cửa sổ, scikit-learn 1.9.1). Thử nghiệm live đạt độ chính xác cao: trạng thái nghỉ $\to$ `BENIGN`, SYN 1 nguồn $\to$ `DoS`, SYN spoof $\to$ `DDoS` trên cả nhánh Luật ngưỡng và nhánh AI.

### Thêm mới

- **Quy trình tập dữ liệu cửa sổ từ file PCAP** phục vụ huấn luyện Học máy (Machine Learning), song song với `build_window_dataset.py` (được giữ làm phương án dự phòng). Tạo module `detection/window_features.py` làm nguồn chân lý duy nhất cho công thức tính toán đặc trưng cửa sổ, được import bởi cả bộ trích xuất offline và detector live để đảm bảo tính đồng nhất 100%; module định nghĩa `FEATURES` (10 đặc trưng cung cấp live: 9 đặc trưng chuẩn + `rate_per_src = pps/max(n_src,1)`) và tập mở rộng `EXTRACT` (bổ sung `icmp_s`, `udp_ratio`, `avg_pkt_size`). Tạo `attacks/benign_gen.py` sinh lưu lượng người dùng hợp lệ ngẫu nhiên cho lớp `BENIGN` thực tế. Script `experiments/capture_session.py` điều phối 14 pha kịch bản trong Docker lab, chạy `tcpdump -s 100` trong container detector và ghi nhận mốc thời gian host-clock timeline. `ml/pcap_to_windows.py` trích xuất các cửa sổ trượt (1.0s / stride 0.5s) và gán nhãn theo timeline. Script `ml/train_window.py` import `FEATURES` từ module dùng chung, **bỏ phép chia ngẫu nhiên 70/30** (tránh rò rỉ dữ liệu giữa các cửa sổ chồng lấn), đánh giá duy nhất bằng **Leave-One-Run-Out (LORO)** (1 pcap = 1 run) và xuất độ quan trọng đặc trưng (Feature Importance).
- **Kịch bản `http_flood.py --pps`**: Điều tiết tốc độ yêu cầu/giây trên toàn bộ các luồng worker (mặc định `0` = không giới hạn). Tương tự như `syn_flood.py --pps`, giúp các kịch bản thu thập L7 được giới hạn ở tốc độ gói thực tế thay vì hàng chục nghìn pps ảo của bridge Docker, tránh hiện tượng lệch phân phối dữ liệu so với mạng WiFi máy thật.
- **Vector tấn công UDP flood**: Nhóm tấn công thứ 3 (tầng giao vận/mạng volumetric L3/4), bên cạnh SYN (L4) và HTTP (L7). Tạo mới script `attacks/udp_flood.py` tương tự `syn_flood.py` (sử dụng Scapy `IP()/UDP()`, hỗ trợ `--spoof`, `--pps`, `--count`, `--size`). Detector hỗ trợ đếm UDP trên cả hai engine (Scapy và eBPF), bổ sung cột `udp_s` trong CSV và trường `udp` trong JSON stream, gắn nhãn `[UDP flood]` khi `udp_s >= --pps` và `udp_s > syn_s`. Bổ sung chế độ UDP vào các script điều phối: `run_ddos.sh udp` và `run_ddos_remote.sh udp`.
- **Hỗ trợ triển khai mạng máy thật (Physical Multi-Machine)**: Chạy bài lab trên các máy tính xách tay Linux thật thông qua mạng WiFi nội bộ dùng chung mà không làm ảnh hưởng đến môi trường Docker lab. Bổ sung script `run_ddos_remote.sh` điều phối các máy tấn công từ xa qua giao thức SSH bằng cờ lặp `-a user@ip`. Bổ sung tài liệu `docs/MULTI_MACHINE.md` (tiếng Việt) hướng dẫn mô hình 3 máy, dò IP DHCP, các lệnh kịch bản và phân quyền `CAP_NET_RAW` cho raw socket qua SSH.
- **Chế độ tấn công công suất tối đa (Max-Intensity Mode)** (`intensity=paced|max`): Chế độ `max` kích hoạt các công cụ phát tải ở tốc độ dây (line-rate) thay cho Scapy/urllib — gồm `hping3 -S --flood` (SYN, `--rand-source` để spoof) và `ab -k -c 500` (L7) cho các kịch bản A/B/C, tự động chuyển sang engine `--engine ebpf`. Tích hợp vào `experiments/run_scenarios.py`, `run_ddos.sh` và công tắc gạt **"Max intensity"** trên Dashboard.
- **Đo đạc tác động thực tế của bão gói line-rate** (chế độ chỉ phát hiện, không chặn): Ghi nhận A-max ~190k pps, B-max ~123k pps, C-max ~693k pps mà **không làm rớt gói tại card mạng `eth0`**, đồng thời người dùng hợp lệ vẫn nhận phản hồi **100% mã 200 OK** nhờ nhân Linux hiện đại kích hoạt SYN cookies và máy chủ Nginx tĩnh tối ưu (độ trễ p95 chỉ tăng từ 1ms lên 11ms). Khi kích hoạt cơ chế chặn `--block`, A-max bị hủy gần 100% tại XDP và C-max giảm mạnh từ ~433k pps xuống ~28 pps, kéo độ trễ phản hồi về mức 1ms.
- **Cơ chế chặn gói tự động trong nhân Linux qua eBPF `XDP_DROP`** (`detection/detector.py --block`, yêu cầu `--engine ebpf`): Chương trình XDP **đếm gói trước, hủy gói sau**: các IP nguồn có tốc độ vượt ngưỡng `--block-pps` sẽ bị đưa vào BPF map `blocklist` kèm thời gian sống TTL (`--block-ttl`, tự động hết hạn — không khóa vĩnh viễn) và bị hủy gói; cờ `--block-syn-rate N` bổ sung cơ chế token bucket cho gói SYN toàn cục trong kernel để cắt giảm bão gói SYN spoof ngẫu nhiên. Báo cáo số lượng nguồn bị chặn và số gói bị drop (`blocked_src`/`blocked_pps`) lên bảng điều khiển thời gian thực.
- **Engine đếm gói eBPF/XDP cho Detector** (`detection/detector.py --engine scapy|ebpf`, mặc định `scapy`): `detection/ebpf_counter.py` nạp chương trình **XDP ingress** vào card `eth0` của máy nạn nhân, đếm gói tin/SYN/ACK và phân bố IP nguồn/cổng đích trực tiếp vào BPF maps và luôn trả về `XDP_PASS` (chế độ chỉ phát hiện). Trong bài kiểm thử 120,000 gói tin tốc độ cao, engine Scapy chỉ bắt được **57%** (đạt ngưỡng xử lý tối đa ~6.9k pps), trong khi engine XDP bắt chính xác **95%** và ghi nhận đúng đỉnh ~30k pps.
- **Ảnh biểu ngữ SVG dự án (`banner.svg`)**, hiển thị trang trọng ở đầu tài liệu `README.md`.
- **Cơ chế ngưỡng thích nghi EWMA trong Detector (`--adaptive`)**: Ngưỡng động tính theo công thức `μ + k·MAD` với sàn tối thiểu `--pps/--syn`, tự động đóng băng việc học đường cơ sở trong thời gian diễn ra cảnh báo.
- **Script đánh giá kiểm thử ngưỡng cố định vs ngưỡng thích nghi (`experiments/adaptive_eval.py`)** và đồ thị kết quả (`assets/adaptive_eval.png`), chứng minh ngưỡng thích nghi vừa bắt được tấn công khi baseline thấp, vừa triệt tiêu báo động giả khi lưu lượng hợp lệ tăng trôi theo thời gian.
- **Tài liệu lý thuyết Markdown (`docs/LyThuyet_DoS_DDoS.md`)** phục vụ nghiên cứu và thuyết minh, bao gồm cơ sở lý thuyết DoS/DDoS, thuật toán entropy và cơ chế thích nghi.
- **Quy trình Học máy trên tập dữ liệu CICDDoS2019**: Huấn luyện Random Forest và HistGradientBoosting trên các đặc trưng cấp luồng, so sánh với luật ngưỡng đơn và trực quan hóa ma trận nhầm lẫn (Confusion Matrix).
- **Hỗ trợ cờ `detector.py --stream`**: Xuất luồng dữ liệu JSON định kỳ mỗi giây ra stdout phục vụ Web Dashboard, đồng thời giữ nguyên bảng console và đầu ra log CSV.
- **Bảng điều khiển phòng thủ thời gian thực (`dashboard/`, Node.js + Express + WebSocket)**: Giám sát sơ đồ mạng, kiểm tra sức khỏe dịch vụ web (Service Health Probe) và điều khiển tấn công trực quan.

### Đã sửa

- Engine eBPF không còn bị treo khi gặp bão gói SYN flood `--rand-source`: BPF hash map `src_ip` được **giới hạn kích thước tối đa 8,192 mục** (thay vì 65,536), giúp khống chế thời gian đọc/xóa map từ userspace trong mỗi cửa sổ 1 giây. Số lượng gói tin/SYN/ACK (PERCPU) luôn chính xác tuyệt đối; chỉ số `n_src` chạm ngưỡng tối đa (~8192) vẫn thể hiện rõ bản chất phân tán cao độ của đòn DDoS ($H(src) \approx 13$).
- Khi thoát Dashboard, hệ thống tự động tắt tiến trình detector **bên trong container** (`docker exec detector pkill -f detector.py`), thay vì chỉ ngắt tiến trình `docker exec` ở máy host.
- Image container detector (`detection/Dockerfile`) được bổ sung đầy đủ thư viện `scikit-learn==1.9.1` và `joblib==1.6.0`, khắc phục lỗi thiếu module khi kích hoạt `--ml`.
- Detector lập tức thoát và báo lỗi rõ ràng nếu việc bắt gói thất bại (ví dụ khi khởi động lại container victim làm hỏng network namespace `service:victim`), thay vì im lặng xuất `pps=0`.
- Cơ chế kiểm tra sức khỏe dịch vụ trên Dashboard chạy qua giao diện loopback nội bộ của victim, không còn xuất hiện trên giao diện mạng bị giám sát làm sai lệch số lượng nguồn `n_src`.
- Nhật ký sự kiện Dashboard hiển thị bản ghi mới nhất ở dưới cùng (theo phong cách terminal) và chỉ tự động cuộn khi người dùng đang ở cuối trang.

### Đã xóa

- Script điều phối PowerShell cũ `run_ddos.ps1`: Dự án hiện tại chạy chuẩn mực trên nền tảng Linux và sử dụng script Bash `run_ddos.sh`.
- Cơ chế giới hạn tốc độ Nginx cũ (Rate-limit L7 thủ công): Đã được thay thế hoàn toàn bằng cơ chế phòng thủ tự động trong nhân kernel eBPF/XDP theo vòng lặp khép kín (Closed-loop IPS).

## [1.0.0] - 2026-09-30

Phiên bản phát hành đầu tiên. Ghi nhận toàn bộ trạng thái nền tảng ban đầu của phòng lab, các công cụ tấn công, mô-đun phát hiện, bộ công cụ phân tích và hệ thống tài liệu.

### Thêm mới

- Môi trường ảo hóa Docker Lab cô lập (`docker-compose.yml`): Gồm container `victim` (Nginx), các container tấn công và `detector` chia sẻ chung network namespace trên dải mạng `dos-lab` (`172.30.0.0/24`).
- Tấn công SYN flood (L4) hỗ trợ giả mạo IP nguồn (`attacks/syn_flood.py`).
- Tấn công HTTP flood (L7) đa luồng (`attacks/http_flood.py`).
- Bộ phát hiện thời gian thực (`detection/detector.py`): Giám sát ngưỡng mỗi giây (`pps`, `syn/s`), tính toán Shannon entropy địa chỉ IP nguồn, phân loại đơn nguồn vs phân tán (DoS vs DDoS), và gắn thẻ `[SYN flood]` dựa trên tỷ lệ ACK/SYN.
- Lọc gói tin inbound (`--victim`) để không đếm nhầm các gói tin phản hồi do chính nạn nhân gửi đi.
- Kịch bản chạy tự động các kịch bản chuẩn hóa A/B/C kèm siêu dữ liệu ground-truth (`experiments/run_scenarios.py`).
- Bản demo có hướng dẫn chạy bằng 1 lệnh duy nhất kèm kiểm tra môi trường container (`experiments/demo.py`).
- Công cụ phân tích offline: Vẽ đồ thị timeline (`analysis/plot_attack.py`) và tính toán độ trễ, Precision, Recall, F1 (`analysis/metrics.py`).
- Tập dữ liệu đo đạc và đồ thị hoàn chỉnh lưu tại `results/final/`.
- Hệ thống tài liệu dự án: `README.md`, tài liệu lý thuyết và cẩm nang kiểm thử `docs/TESTING.md`.

[Chưa phát hành]: https://github.com/cityengin/dos-ddos-project/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cityengin/dos-ddos-project/releases/tag/v1.0.0
