FROM python:3.11-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/opt/osv-home \
    XDG_CACHE_HOME=/opt/osv-home/.cache

COPY gitleaks /usr/local/bin/gitleaks
COPY syft /usr/local/bin/syft
COPY osv-scanner /usr/local/bin/osv-scanner
COPY common.py /opt/secmind-tools/common.py
COPY run-gitleaks.py /opt/secmind-tools/run-gitleaks.py
COPY run-syft.py /opt/secmind-tools/run-syft.py
COPY run-osv.py /opt/secmind-tools/run-osv.py
COPY osv-db /opt/osv-home/.cache/osv-scalibr

RUN chmod 0555 /usr/local/bin/gitleaks /usr/local/bin/syft /usr/local/bin/osv-scanner \
        /opt/secmind-tools/run-gitleaks.py /opt/secmind-tools/run-syft.py /opt/secmind-tools/run-osv.py \
    && chmod 0444 /opt/secmind-tools/common.py \
    && find /opt/osv-home -type f -exec chmod 0444 {} \; \
    && mkdir -p /output /tmp \
    && chmod 1777 /output /tmp \
    && useradd --system --uid 65532 --no-create-home sandbox

USER 65532:65532
ENTRYPOINT ["python", "/opt/secmind-tools/run-gitleaks.py"]
