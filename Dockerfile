FROM python:3.12-slim

# Chromium is only needed for PDF export; every other format works without it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV WEBSCAN_CHROME=/usr/bin/chromium \
    WEBSCAN_CACHE_DIR=/cache \
    WEBSCAN_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY webscan ./webscan
RUN pip install --no-cache-dir ".[web,cli]"

RUN useradd --create-home --uid 10001 scanner \
 && mkdir -p /cache /data && chown scanner /cache /data
USER scanner

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"
ENTRYPOINT ["webscan"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
