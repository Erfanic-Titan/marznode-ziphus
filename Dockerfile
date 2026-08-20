# Sidecar backends. Both were unpinned upstream, and jklolixxs/sing-box has
# since disappeared from Docker Hub entirely, which breaks the build outright.
# Use SagerNet's official image and pin both.
ARG HYSTERIA_IMAGE=tobyxdd/hysteria:v2.12.1
ARG SING_BOX_IMAGE=ghcr.io/sagernet/sing-box:v1.13.19

FROM ${HYSTERIA_IMAGE} AS hysteria-image
FROM ${SING_BOX_IMAGE} AS sing-box-image

FROM python:3.12-alpine

# Pin the core. The upstream install-release.sh always fetches "latest", which
# means two builds of the same commit can ship different xray versions and a
# rebuild can silently change protocol behaviour on a live node.
ARG XRAY_VERSION=v26.7.28

ENV PYTHONUNBUFFERED=1

COPY --from=hysteria-image /usr/local/bin/hysteria /usr/local/bin/hysteria
COPY --from=sing-box-image /usr/local/bin/sing-box /usr/local/bin/sing-box

WORKDIR /app

COPY . .

RUN mkdir /etc/init.d/

RUN apk add --no-cache curl unzip

RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"; \
    curl -fsSL -o xray.zip.dgst \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip.dgst"; \
    grep -i 'SHA2-256' xray.zip.dgst | head -1 | awk '{print $NF"  xray.zip"}' > xray.sha256; \
    sha256sum -c xray.sha256; \
    mkdir -p xray-unpack /usr/local/lib/xray; \
    unzip -o xray.zip -d xray-unpack; \
    install -m 0755 xray-unpack/xray /usr/local/bin/xray; \
    install -m 0644 xray-unpack/geoip.dat xray-unpack/geosite.dat /usr/local/lib/xray/; \
    rm -rf xray.zip xray.zip.dgst xray.sha256 xray-unpack; \
    xray version

RUN apk add --no-cache alpine-sdk libffi-dev && pip install --no-cache-dir -r /app/requirements.txt && apk del -r alpine-sdk libffi-dev curl unzip

CMD ["python3", "marznode.py"]
