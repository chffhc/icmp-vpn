# Isolated local integration test image, not a production service.
FROM nikolaik/python-nodejs:python3.11-nodejs20
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables tcpdump && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir cryptography==46.0.3
WORKDIR /work
