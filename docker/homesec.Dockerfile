# syntax=docker/dockerfile:1.7
#
# Image for this project's two services. Build context: the repository root.
# async-vuln-scanner comes in as the named build context "scanner"
# (docker-compose.yml: additional_contexts), by default straight from GitHub:
#
#   docker build -f docker/homesec.Dockerfile --target homesec \
#     --build-context scanner=https://github.com/rosko35/async-vuln-scanner.git#main .
#
# Targets:
#   homesec    scan, SIEM export, syslog receiver. No capabilities at all.
#   discovery  adds ONE extra binary, a copy of the Python interpreter with the
#              cap_net_raw file capability, used only by the discovery service
#              for Scapy ARP sweeps while still running as an unprivileged user.

FROM python:3.12-slim-bookworm AS homesec

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY --from=scanner pyproject.toml README.md LICENSE /tmp/async-vuln-scanner/
COPY --from=scanner src /tmp/async-vuln-scanner/src
RUN pip install /tmp/async-vuln-scanner && rm -rf /tmp/async-vuln-scanner

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# [arp] pulls in Scapy (pure Python); only the discovery service can use it.
RUN pip install ".[arp]" && rm -rf /root/.cache

COPY config ./config

RUN useradd --system --uid 10001 --gid nogroup --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin homesec \
    && mkdir -p /data /router-logs \
    && chown homesec:nogroup /data /router-logs

USER 10001

ENV HOMESEC_CONFIG=/app/config/homesec.yml \
    HOMESEC_DB=/data/homesec.db \
    HOMESEC_REPORTS_DIR=/data/reports \
    HOMESEC_SYSLOG_DIR=/router-logs \
    VULNSCAN_CACHE_DIR=/data/nvd-cache

ENTRYPOINT ["homesec"]
CMD ["run"]


FROM homesec AS discovery

USER root
# setcap lives in libcap2-bin; it is removed again in the same layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && cp "$(readlink -f /usr/local/bin/python3)" /usr/local/bin/python3-netraw \
    && setcap cap_net_raw+ep /usr/local/bin/python3-netraw \
    && apt-get purge -y libcap2-bin \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
USER 10001

ENTRYPOINT ["python3-netraw", "-m", "homesec"]
CMD ["run", "--only", "discovery"]
