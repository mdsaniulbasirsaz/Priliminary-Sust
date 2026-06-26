FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

COPY app/ app/


FROM python:3.11-slim

RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app

WORKDIR /app

COPY --from=builder /app/deps /app/deps
COPY --from=builder /app/app /app/app

ENV PYTHONPATH=/app/deps:$PYTHONPATH \
    PATH=/app/deps/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    UVICORN_WORKERS=4

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

RUN printf '#!/bin/sh\nset -e\nexec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers "${UVICORN_WORKERS:-4}" --limit-concurrency 128 --timeout-graceful-shutdown 30\n' > /entrypoint.sh && chmod 755 /entrypoint.sh

RUN chown -R app:app /app && chown app:app /entrypoint.sh

USER app

CMD ["/entrypoint.sh"]
