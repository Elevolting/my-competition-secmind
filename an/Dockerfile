FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system security_agent && useradd --system --gid security_agent --home /app security_agent

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install ".[postgres,qdrant]"

RUN mkdir -p /app/data/inputs /app/data/uploads /app/data/runs \
    && chown -R security_agent:security_agent /app
USER security_agent

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["uvicorn", "security_agent.api:app", "--host", "0.0.0.0", "--port", "8000"]

