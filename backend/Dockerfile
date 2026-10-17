# RevDroid backend: Python + JRE + apktool + jadx in one image.
# Build context is the project root (see docker-compose.yml).
FROM python:3.12-slim-bookworm

ARG APKTOOL_VERSION=3.0.3
ARG JADX_VERSION=1.5.6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REVDROID_DATA_DIR=/data \
    REVDROID_TOOLS_DIR=/opt/tools

RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jre-headless ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/install_tools.py /tmp/install_tools.py
RUN APKTOOL_VERSION=$APKTOOL_VERSION JADX_VERSION=$JADX_VERSION python /tmp/install_tools.py \
 && rm /tmp/install_tools.py

COPY backend/app ./app

# never run the analyzer as root: it handles untrusted files
RUN useradd --create-home --uid 10001 revdroid && mkdir -p /data && chown revdroid /data
USER revdroid

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=8).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
