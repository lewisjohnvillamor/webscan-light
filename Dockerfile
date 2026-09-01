FROM python:3.12-slim

# Chromium is only needed for PDF export; every other format works without it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV WEBSCAN_CHROME=/usr/bin/chromium \
    WEBSCAN_CACHE_DIR=/cache \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY webscan ./webscan
RUN pip install --no-cache-dir ".[web,cli]"

RUN useradd --create-home --uid 10001 scanner \
 && mkdir -p /cache && chown scanner /cache
USER scanner

EXPOSE 8000
ENTRYPOINT ["webscan"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
