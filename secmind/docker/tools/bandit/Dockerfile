FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install "bandit==1.9.4" \
    && mkdir -p /opt/secmind-bandit \
    && useradd --system --uid 65532 --no-create-home sandbox
COPY docker/tools/bandit/run.py /opt/secmind-bandit/run.py
RUN chmod 0555 /opt/secmind-bandit/run.py
USER 65532:65532
ENTRYPOINT ["python", "/opt/secmind-bandit/run.py"]
