FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3 tcpdump iproute2 curl procps \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir scapy
WORKDIR /app
CMD ["sleep", "infinity"]