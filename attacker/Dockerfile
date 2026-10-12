FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3 apache2-utils tcpdump iproute2 curl procps \
    && rm -rf /var/lib/apt/lists/*
# scapy: craft/sniff raw packets. scikit-learn + joblib: nap model ML cua detector (--ml).
# Pin scikit-learn 1.9.1 khop host luc train de nap .joblib khong loi lech phien ban.
RUN pip install --no-cache-dir scapy scikit-learn==1.9.1 joblib==1.6.0
WORKDIR /app
CMD ["sleep", "infinity"]