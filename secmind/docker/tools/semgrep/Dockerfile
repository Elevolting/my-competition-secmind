FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    SEMGREP_SEND_METRICS=off

RUN pip install "semgrep==1.110.0" \
    && mkdir -p /opt/secmind-tools /opt/secmind-rules \
    && useradd --system --uid 65532 --no-create-home sandbox
COPY docker/tools/semgrep/run.py /opt/secmind-tools/run-semgrep
COPY docker/tools/semgrep/rules/reviewed /opt/secmind-rules
RUN chmod 0555 /opt/secmind-tools/run-semgrep \
    && find /opt/secmind-rules -type f -exec chmod 0444 {} \;
USER 65532:65532
ENTRYPOINT ["python", "/opt/secmind-tools/run-semgrep"]
