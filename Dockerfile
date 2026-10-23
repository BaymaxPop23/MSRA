FROM python:3.11-slim

# System dependencies for weasyprint + jadx
RUN apt-get update && apt-get install -y --no-install-recommends \
    # jadx runtime
    default-jre-headless \
    wget \
    unzip \
    # weasyprint system libs
    libpango-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    # adb
    adb \
    && rm -rf /var/lib/apt/lists/*

# Install jadx (pin the release; pass JADX_SHA256=<sum> to verify the download)
ARG JADX_VERSION=1.5.0
ARG JADX_SHA256=""
RUN wget -q https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip \
    -O /tmp/jadx.zip \
    && if [ -n "$JADX_SHA256" ]; then echo "$JADX_SHA256  /tmp/jadx.zip" | sha256sum -c -; fi \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Unprivileged runtime user; the DB lives on the data volume
RUN useradd --create-home --uid 10001 msra \
    && mkdir -p uploads reports data/custom \
    && chown -R msra:msra /app
USER msra

EXPOSE 5001

ENV PORT=5001 \
    MSRA_DB_PATH=/app/data/custom/msra.db

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD python3 -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/api/queue/status' % os.environ.get('PORT','5001'), timeout=4)" || exit 1

# Binding 0.0.0.0 is required inside the container; docker-compose publishes
# the port on 127.0.0.1 only. Set MSRA_AUTH_TOKEN before exposing it further.
CMD ["python3", "server.py", "--port", "5001", "--host", "0.0.0.0"]
