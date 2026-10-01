FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PROTECTARR_CONFIG=/config/config.yml
WORKDIR /app
COPY pyproject.toml README.md ./
COPY protectarr ./protectarr
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir . && mkdir -p /config /quarantine && chmod 777 /config /quarantine

# Runs as 1000:1000 unless the container sets its own user (match it to qBittorrent's PUID:PGID).
USER 1000:1000
EXPOSE 9797
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '9797'))"
CMD ["protectarr"]
