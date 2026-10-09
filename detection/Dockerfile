# Image rieng cho DETECTOR (tach khoi image attacker de khong lam phinh no).
# Them eBPF/BCC (python3-bpfcc) de dem goi o line-rate bang XDP; van giu scapy lam engine mac dinh.
# Base ubuntu:24.04 de bcc (0.29) khop kernel host (container dung chung kernel host).
# Chi dung trong lab co lap.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-bpfcc \
      python3-scapy \
      curl iproute2 procps tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
CMD ["sleep", "infinity"]
