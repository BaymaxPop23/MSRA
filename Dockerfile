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

# Install jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir flask weasyprint anthropic

# Copy application
COPY . .

# Runtime directories
RUN mkdir -p uploads reports data/custom

EXPOSE 5001

ENV PORT=5001

CMD ["python3", "server.py", "--port", "5001", "--host", "0.0.0.0"]
