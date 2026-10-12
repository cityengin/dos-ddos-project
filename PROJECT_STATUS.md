# DoS/DDoS Attack & Detection - Project Status

## De tai
Thuc hien tan cong DoS/DDoS va phat hien tan cong DoS/DDoS. Do an cuoi ki.
Moi truong: Ubuntu native (Docker khong qua WSL2 -> nhanh/on dinh hon). Truoc day chay tren
Windows + Docker Desktop (WSL2); cac so lieu "before" van giu de so sanh. Lab co lap hoan toan,
KHONG nham target that. Luu y: `docker` can chay qua `sg docker -c '...'` neu phien dang nhap chua
reload nhom docker (hoac re-login / `newgrp docker`).

## Kien truc lab (docker-compose.yml)
- victim: nginx:alpine, IP 172.30.0.10, map ra localhost:8080
- attacker1..6: IP 172.30.0.21..26, co scapy + hping3 + ab (apache2-utils), cap NET_RAW+NET_ADMIN (6 nguon that cho L7)
- detector: dung chung network namespace voi victim (network_mode: service:victim), sniff eth0
- network dos-lab: bridge, subnet 172.30.0.0/24

## Cac file
- attacker/Dockerfile        : image tan cong (python3-slim + hping3 + ab/apache2-utils + scapy + tcpdump)
- attacks/syn_flood.py        : SYN flood L4, co --spoof (random source IP)
- attacks/http_flood.py       : HTTP flood L7, multi-thread GET
- run_ddos.ps1                : orchestrator PowerShell (Windows), chay 6 attacker song song (mode syn|http)
- run_ddos.sh                 : orchestrator bash (Linux), tuong duong run_ddos.ps1 (-i paced|max; tu re-exec qua sg docker)
- experiments/bench_syn_throughput.sh: do pps sinh goi SYN (2 diem, khu khoi dong) 1 va 6 nguon
- detection/detector.py       : sniffer realtime, tinh pps/syn/ack + entropy(src IP) + entropy(dport), phan loai DoS/DDoS, option --csv, --victim
- experiments/run_scenarios.py: chay lai A/B/C tu dong -> detection/{A,B,C}.csv + {A,B,C}.meta.json (--intensity paced|max)
- analysis/plot_attack.py     : ve do thi tu CSV (pps/syn/ack symlog + H_src/n_src), to vung tan cong A/B/C
- analysis/metrics.py         : tach episode, tinh detection time / FP / FN / bang phan loai vs ground truth

## Detector - logic phat hien
- Backend dem goi: --engine scapy (mac dinh) | ebpf. eBPF/XDP dem chinh xac o line-rate (scapy rot
  goi khi pps cao). Code: detection/ebpf_counter.py (BCC, XDP ingress tren eth0 netns victim, chi dem
  KHONG drop, maps packets/syn/ack + src_ip + dport). Detector image rieng (detection/Dockerfile,
  ubuntu+python3-bpfcc) + cap_add CAP_BPF/PERFMON/NET_ADMIN + mount /lib/modules,/usr/src,/sys/kernel/debug.
  So sanh (gui chinh xac 120000 goi toc do cao): scapy DEM 67917/120000 (57%, dinh 6.9k pps) vs
  eBPF 113764/120000 (95%, dinh 30.1k pps). Test 5000 goi toc do thap: eBPF 4986 (~dung, khong trung).
  Moi output giu nguyen (pps/syn_s/ack_s/h_src/h_dport/n_src + luat + --adaptive + --ml + --stream + --csv).
  LUU Y: map src_ips bi CAP 8192 (truoc 65536) -> readback+clear moi window khong con khung khi SYN spoof
  --rand-source sinh hang chuc nghin IP/giay; counters packets/syn/ack o PERCPU van chinh xac, chi n_src
  bao hoa ~8192 (van ro la "rat nhieu nguon" -> DDoS, H_src~13).
- CLOSED-LOOP IPS (phat hien -> tu chan, chi engine ebpf): cac co --block (mac dinh TAT = detect-only),
  --block-pps (vd 200), --block-ttl (vd 5s), --block-syn-rate (vd 2000; 0=tat). eBPF DEM TRUOC roi moi
  chan: blocklist[src]=expire_ns -> XDP_DROP (co TTL, tu het han); token-bucket SYN toan cuc (bpf_spin_lock)
  cat SYN vuot rate (xu SYN spoof). Userspace moi window: nguon vuot --block-pps -> vao blocklist; don muc
  het han; report blocked_src/blocked_pps. An toan: TTL tu het han, client hop le + health-probe toc do
  thap (<< block-pps) khong bi chan nham. Demo before/after (drop live):
  - C (6 nguon HTTP, co trang thai): KHONG chan pps ~136000 -> CO chan pps sup con ~242 (6 nguon bi chan;
    drop SYN -> bat tay khong xong -> attacker treo). Client hop le 200=12/12, latency ~0-1ms ca 2 (nginx
    van tru; gia tri la go tai tan cong).
  - B (SYN spoof): per-source KHONG an (0 nguon bi chan, moi goi 1 IP moi) -> dung giOi han. Bat
    --block-syn-rate 2000: drop ~22000/25866 pps (~85%) SYN spoof, con ~3800 toi nginx (cap ~rate+burst);
    danh doi: rot mot it SYN hop le. (Luu y: SIGKILL khong go XDP; khi detector khoi dong lai tu go XDP cu.)
- Cua so 1 giay. Nguong dang dung: --pps 40 --syn 25
- --victim 172.30.0.10: CHI dem goi inbound toi victim (bo goi victim tu tra ve) -> n_src/ack chinh xac
- Threshold: alert khi pps>=nguong HOAC syn>=nguong
- Phan loai: n_src>=2 => DDoS, nguoc lai => DoS  (dung so nguon lam tieu chi chinh)
- SYN flood: nhan dien khi ack < syn*0.2 (half-open)
- Entropy: H(src) dinh luong muc phan tan (DoS=0, DDoS-spoof ~6, HTTP-3-nguon ~1.58)
- --adaptive: nguong THICH NGHI EWMA (mu + k*MAD, san = --pps/--syn), dong bang hoc khi dang alert.
  Thi nghiem so sanh: experiments/adaptive_eval.py -> assets/adaptive_eval.png (fixed thua, adaptive thang)
- ML: ml/train.py (RF + HistGB) vs luat nguong. CHAY TREN CICDDoS2019 THAT (tai qua kagglehub:
  dhoogla/cicddos2019, ban parquet da lam sach, ~131k flow x 63 dac trung, 13 ho tan cong).
  Phat hien tan cong (nhi phan): luat nguong F1 0.60 -> RF F1 0.999 (HistGB 0.996).
  Phan loai da lop: accuracy 0.93, macro-F1 0.735 (da gom nhan DrDoS_X va X ve 1 ho; --raw-labels
  giu 18 nhan goc -> macro-F1 0.535, chenh lech la do CICDDoS2019 dat nhan 2 kieu theo ngay chup).
  Mau synthetic (ml/make_synthetic.py) van giu lam fallback khi khong tai dataset.
- ML MUC-CUA-SO (cho detector ML live): ml/build_window_dataset.py sinh dataset tu chinh dac trung
  detector (pps,syn,ack,H(src),H(dport),n_src + syn_ratio,ack_syn_ratio), ml/train_window.py train
  1 RandomForest da lop (BENIGN/DoS/DDoS) -> detection/window_model.joblib (sklearn 1.9.1).
  Them 2 kich ban GAN NGUONG: D (SYN spoof cham ~24pps, duoi nguong -> luat bo sot) va E (HTTP 1 nguon
  tai cao -> luat bao nham). Dataset 316 window (BENIGN 162/DDoS 114/DoS 40), 48% window tan cong duoi
  nguong. Ket qua (70/30): F1 phat hien luat 0.58 vs RF 0.99; macro-F1 luat 0.59 vs RF 0.99; window
  duoi nguong luat bat 0% vs RF 100%. LORO: F1 luat 0.52 vs RF 0.99. RF khong con 1.000 (sai ~1 window
  gan nguong); muon RF tut sau hon can E flash-crowd NHIEU nguon (trung voi HTTP-DDoS).
  Phase 3 DA XONG: detector.py co co --ml PATH (nap window_model.joblib, phan loai moi window SONG SONG
  voi luat; hien ca 2 o bang/--stream/--csv; fail RO neu thieu model/sklearn). Da them scikit-learn
  1.9.1 + joblib vao attacker/Dockerfile. Kiem tra live: baseline->BENIGN, A->DoS, B/C->DDoS (khop);
  window HTTP 1-nguon dau pha C doc BENIGN do tin thap (hanh vi hoc tu E).
  Phase 4 DA XONG: dashboard hien verdict ML canh verdict luat (server tu bat --ml khi co model;
  o Attack panel: "rule: X" + dong "ML: Y . conf%", to mau theo verdict ML -> thay ngay khi 2 ben khac nhau).
  Dashboard cung co nut "Blocking ON/OFF" + tile blocked/s: bat -> server restart detector voi
  --engine ebpf --block (XDP_DROP); demo C: pps sup ~15k -> ~36 khi chan. Mac dinh TAT (detect-only).
  (Guard detStarting trong server.js: chi 1 luong startDetector chay -> tranh restart chong cheo khi toggle.)
- Phong thu: DA GO phan mitigation L7 (rate-limit) roi, se lam lai theo huong closed-loop
  (phat hien -> tu dong chan) sau. Hien detector chi phat hien (IDS).

## Ket qua da co (so lieu that tu lab)
- Baseline (baseline.csv, 62s idle): pps=syn=ack=0, 0 episode, 0 false positive -> nguong an toan
  - Ubuntu native: xac nhan lai 63s idle -> pps=syn=ack=0, 0 episode, 0 FP (nguong 40/25 van an toan)
- Validate lai tren Ubuntu (experiments/run_scenarios.py): A=DoS, B=DDoS, C=DDoS -> 3/3 dung,
  detect=0s, FP=0, FN=0. So lieu C trung gan nhu tung chu so voi ban Windows (pps 1811, ack 1428,
  H_src 2.58) -> lab tai lap on dinh tren Ubuntu.
- Throughput sinh goi SYN (bench_syn_throughput.sh, tha rong --pps 0, co spoof, do 2 diem 6s/16s):
  1 nguon ~1470 pps; 6 nguon ~9460 pps tong (~1576 pps/nguon). => kich ban B (pacing 400x6=2400 pps)
  bi gioi han boi PACING, khong phai tran phan cung. (Chua co so Windows "tha rong" tuong duong de
  tinh % chenh lech chinh xac; chay cung script tren may Windows/WSL de co so sanh cong bang.)
- BEFORE fix (attack.csv, detector cu dem ca 2 chieu) -> phan loai chi 2/3, A bi nham DDoS. Giu lam bang chung.
- AFTER fix (detector --victim, moi kich ban 1 file, detection=0s, FP=0, do thi analysis/{A,B,C}.png):
  - A) DoS 1 nguon SYN       : pps ~300  syn ~150  ack 0     n_src=1     H_src=0.00  -> DoS  [SYN flood]  (DUNG)
  - B) DDoS 6 nguon SYN+spoof: pps ~4000 syn ~2000 ack 0     n_src ~2300 H_src ~11.1 -> DDoS [SYN flood]  (DUNG)
  - C) DDoS 6 nguon HTTP L7  : pps ~1800 syn ~400  ack ~1400 (ACK>>SYN) n_src=6 H_src ~2.58 -> DDoS L7 (DUNG)
  (so lieu do qua dashboard sau khi nang len 6 attacker + syn_flood --pps; B spoof toc do cao -> n_src len hang nghin)
- Do chinh xac phan loai: 3/3 (truoc khi sua la 2/3).

## Cuong do toi da (intensity=max) + do tac dong that
- Che do: paced (scapy, mac dinh, cho dataset ML - GIU NGUYEN) | max (hping3/ab line-rate, CHI A/B/C, can engine eBPF).
  Wire: run_scenarios.py --intensity/--max-rate/--max-conc; run_ddos.sh -i paced|max; dashboard nut "Max intensity"
  (detector dashboard gio LUON chay engine eBPF nen doi max khong can restart detector).
- Do qua eth0 rx counter cua victim (detect-only, KHONG block; host 20 core, 10.5GB trong; 8s/trang thai):
  - idle   : ~28 pps   |           | client 30/30 OK | p50/p95 = 1/1 ms | host load ~0.3
  - A-max  : ~190k pps | rx drop 0 | client 37/37 OK | p95 1ms  | host load ~0.9  (1 nguon SYN --flood; detector thay ~270k pps luc dinh)
  - B-max  : ~123k pps | rx drop 0 | client 36/36 OK | p95 1ms  | host load ~1.7  (6 nguon SYN --rand-source --flood)
  - C-max  : ~693k pps | rx drop 0 | client 35/35 OK | p95 11ms | host load ~3.7  (6 nguon ab -k -c 500; ~55.7k req/s/nguon, ~330k req/s tong, 0 loi)
  (load 0.9/1.7/3.7 tren 20 core -> host KHONG nghen o bat ky trang thai nao; tai tang theo khoi luong tan cong)
- KET LUAN TRUNG THUC: mac dinh hien dai (SYN cookies + nginx tinh rat nhanh) HAP THU sach ca 3 -> 0 goi rot o eth0
  ke ca 693k pps, client hop le 100% thanh cong; tac dong nang nhat chi la duoi latency C 1ms->11ms. Muon victim
  SAP that can victim yeu hon / quy mo lon hon nhieu. Khong thoi phong = ket luan hop le.
- Hoi phuc khi bat --block (phong thu = GIAM khoi luong + tai host + tra lai latency, khong phai cuu dich vu da chet):
  - A-max: XDP drop ~100% (blocked_src=1, drop ~460k pps), client 39/39 OK, p95 1ms
  - C-max: pps ~433k -> ~28 (blocked_src=6), client 41/41 OK, p95 11ms -> 1ms
  - B-max (spoof): per-source vo dung -> --block-syn-rate cat ~85% (nhu phan closed-loop)

## Phat hien / loi da xac dinh (DA SUA)
- BUG phan loai: detector sniff o netns cua victim nen thay CA goi victim tu tra ve (SYN-ACK, src=IP victim).
  -> kich ban A (1 nguon that) bi dem thanh n_src=2 => gan nham DDoS.
  -> ack cung bi thoi phong boi SYN-ACK cua victim nen co "[SYN flood]" (ack<syn*0.2) khong kich hoat dung.
- DA SUA: them --victim, on_packet chi dem goi INBOUND (dst == victim). Sau khi sua: A -> n_src=1, ack=0
  => DoS [SYN flood] dung; B/C van dung. So sanh before/after la mot diem manh de trinh bay trong bao cao.

## Con lai (TODO)
- [x] Do baseline chinh thuc (baseline.csv) -> xac nhan nguong (0 FP)
- [x] Chay 3 kich ban A/B/C ghi CSV rieng + ground truth (experiments/run_scenarios.py -> {A,B,C}.csv/.meta.json)
- [x] Ve do thi tu CSV (analysis/plot_attack.py -> analysis/{A,B,C}.png, attack.png)
- [x] Tinh metric: detection time, FP/FN, bang phan loai (analysis/metrics.py) -> 3/3
- [x] Sua BUG phan loai (inbound-only) roi chay lai A/B/C de validate
- [x] ML voi dataset CICDDoS2019 THAT (kagglehub dhoogla/cicddos2019): rule F1 0.60 -> RF 0.999;
      phan loai ho tan cong accuracy 0.93 / macro-F1 0.735
- [ ] Viet bao cao (da co: bang so lieu before/after, 4 do thi, cac gioi han)

## Gioi han da biet (de bao ve)
- 1 may spoof nhieu IP KHONG phan biet duoc voi nhieu may that tu goc nhin victim (ca hai deu ra "nhieu source IP")
- Threshold nhay cam voi flash crowd (false positive) va bo sot low-and-slow (Slowloris)
- Entropy phu thuoc baseline va do dai cua so
