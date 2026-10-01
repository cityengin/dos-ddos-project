# DoS/DDoS Attack & Detection - Project Status

## De tai
Thuc hien tan cong DoS/DDoS va phat hien tan cong DoS/DDoS. Do an cuoi ki.
Moi truong: Windows + Docker Desktop (WSL2). Lab co lap hoan toan, KHONG nham target that.

## Kien truc lab (docker-compose.yml)
- victim: nginx:alpine, IP 172.30.0.10, map ra localhost:8080
- attacker1/2/3: IP 172.30.0.21/.22/.23, co scapy + hping3, cap NET_RAW+NET_ADMIN
- detector: dung chung network namespace voi victim (network_mode: service:victim), sniff eth0
- network dos-lab: bridge, subnet 172.30.0.0/24

## Cac file
- attacker/Dockerfile        : image tan cong (python3-slim + hping3 + scapy + tcpdump)
- attacks/syn_flood.py        : SYN flood L4, co --spoof (random source IP)
- attacks/http_flood.py       : HTTP flood L7, multi-thread GET
- run_ddos.ps1                : orchestrator PowerShell, chay 3 attacker song song (mode syn|http)
- detection/detector.py       : sniffer realtime, tinh pps/syn/ack + entropy(src IP) + entropy(dport), phan loai DoS/DDoS, option --csv, --victim
- experiments/run_scenarios.py: chay lai A/B/C tu dong -> detection/{A,B,C}.csv + {A,B,C}.meta.json
- analysis/plot_attack.py     : ve do thi tu CSV (pps/syn/ack symlog + H_src/n_src), to vung tan cong A/B/C
- analysis/metrics.py         : tach episode, tinh detection time / FP / FN / bang phan loai vs ground truth

## Detector - logic phat hien
- Cua so 1 giay. Nguong dang dung: --pps 40 --syn 25
- --victim 172.30.0.10: CHI dem goi inbound toi victim (bo goi victim tu tra ve) -> n_src/ack chinh xac
- Threshold: alert khi pps>=nguong HOAC syn>=nguong
- Phan loai: n_src>=2 => DDoS, nguoc lai => DoS  (dung so nguon lam tieu chi chinh)
- SYN flood: nhan dien khi ack < syn*0.2 (half-open)
- Entropy: H(src) dinh luong muc phan tan (DoS=0, DDoS-spoof ~6, HTTP-3-nguon ~1.58)
- --adaptive: nguong THICH NGHI EWMA (mu + k*MAD, san = --pps/--syn), dong bang hoc khi dang alert.
  Thi nghiem so sanh: experiments/adaptive_eval.py -> assets/adaptive_eval.png (fixed thua, adaptive thang)

## Ket qua da co (so lieu that tu lab)
- Baseline (baseline.csv, 62s idle): pps=syn=ack=0, 0 episode, 0 false positive -> nguong an toan
- BEFORE fix (attack.csv, detector cu dem ca 2 chieu) -> phan loai chi 2/3, A bi nham DDoS. Giu lam bang chung.
- AFTER fix (detector --victim, moi kich ban 1 file, detection=0s, FP=0, do thi analysis/{A,B,C}.png):
  - A) DoS 1 nguon SYN      : pps 58  syn 29  ack 0    n_src=1  H_src=0.00 -> DoS  [SYN flood]  (DUNG)
  - B) DDoS 3 nguon SYN+spoof: pps 132 syn 66  ack 0    n_src=66 H_src=6.04 -> DDoS [SYN flood]  (DUNG)
  - C) DDoS 3 nguon HTTP L7  : pps 2196 syn 607 ack 1639 (ACK>>SYN) n_src=3 H_src=1.58 -> DDoS L7 (DUNG)
- Do chinh xac phan loai: 3/3 (truoc khi sua la 2/3).

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
- [ ] (Tuy chon) ML voi dataset CICDDoS2019
- [ ] Viet bao cao (da co: bang so lieu before/after, 4 do thi, cac gioi han)

## Gioi han da biet (de bao ve)
- 1 may spoof nhieu IP KHONG phan biet duoc voi nhieu may that tu goc nhin victim (ca hai deu ra "nhieu source IP")
- Threshold nhay cam voi flash crowd (false positive) va bo sot low-and-slow (Slowloris)
- Entropy phu thuoc baseline va do dai cua so
