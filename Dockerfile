# LocalShield — cross-platform detection core + dashboard image.
#
# This image runs the platform-independent parts of LocalShield: the Streamlit
# dashboard, the YAML detection engine, and the Linux `auth.log` importer.
# Windows-only features (live Event Log capture, firewall auto-response via
# pywin32) are NOT available in the container — use run_localshield.bat on
# Windows for those. `pywin32` is skipped automatically here because
# requirements.txt guards it with `; sys_platform == "win32"`.
FROM python:3.12-slim

# Streamlit/altair are happier with a writable, predictable HOME.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DB_PATH=/data/logs.db

WORKDIR /app

# Install Python dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source.
COPY . .

# Persist the SQLite database (and anything else under /data) via a volume.
# Run as a dedicated non-root user: a compromised dashboard process should
# not have root inside the container.
RUN useradd --create-home --uid 1000 localshield \
    && mkdir -p /data \
    && chown -R localshield:localshield /app /data
VOLUME ["/data"]
USER localshield

EXPOSE 8501

# Streamlit's built-in health endpoint; python stands in for curl (not
# installed in the slim base image).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"

# Bind to 0.0.0.0 *inside* the container. The host must publish this to
# 127.0.0.1 only (see docker-compose.yml) to keep the localhost-only posture,
# since the dashboard has no built-in authentication.
CMD ["streamlit", "run", "dashboard.py", \
     "--server.address=0.0.0.0", "--server.port=8501"]
