# Run 18 reference image for the Device Trust verification service.
# Build:  docker build -t device-trust:0.9.0.dev1 service/
# Pin the base image by digest in your own registry for reproducible deployments.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY device_trust ./device_trust
RUN pip install --disable-pip-version-check . \
 && useradd --system --uid 10001 --home-dir /data trust \
 && mkdir -p /data && chown trust /data

USER trust
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
ENTRYPOINT ["device-trust"]
CMD ["serve", "--policy", "/run/secrets/policy.json", "--db", "/data/devices.sqlite", \
     "--host", "0.0.0.0", "--port", "8080", "--gateway-token-file", "/run/secrets/gateway_token"]
