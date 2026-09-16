FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY threatlens ./threatlens
COPY samples ./samples
COPY alembic.ini ./
COPY alembic ./alembic

RUN pip install --upgrade pip && pip install ".[postgres,otel,redis]"

RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import httpx;httpx.get('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "threatlens.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
