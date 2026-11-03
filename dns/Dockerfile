# DNS reflector cho mo phong DNS Amplification - CHI DUNG TRONG LAB CO LAP.
# bind9 authoritative cho zone amp.lab, KHONG recursion -> KHONG phai open resolver that su
# (chi tra loi cho zone cua minh, co lap trong mang lab). Mot query nho (~40 byte) hoi TXT lon
# tao phan hoi ~2KB = khuech dai ~50x; attacker spoof source=IP victim -> phan hoi doi ve victim.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      bind9 bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY named.conf   /etc/bind/named.conf
COPY db.amp.lab   /etc/bind/db.amp.lab
# -g: chay foreground + log ra stderr (tien cho 'docker logs')
CMD ["named", "-g", "-c", "/etc/bind/named.conf"]
