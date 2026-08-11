# Stage 1: Builder
FROM python:3.11-slim AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment and install Python dependencies
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir fastapi uvicorn dash plotly dash-bootstrap-components
RUN pip install --no-cache-dir "wheel>=0.46.2" "jaraco.context>=6.1.0"
# API hardening deps
RUN pip install --no-cache-dir "python-multipart>=0.0.6" "python-jose[cryptography]>=3.3" "prometheus-client>=0.19" "redis>=5.0" "gunicorn>=21.0" "argon2-cffi>=23.1" "jinja2>=3.1"
# Pin the ML stack so model artifacts load deterministically
RUN pip install --no-cache-dir "scikit-learn==1.9.0" "numpy==2.4.6" "scipy==1.17.1" "joblib==1.5.3"
# Pin cryptography last so it wins over any transitive upgrade
RUN pip install --no-cache-dir "cryptography==43.0.1"

# Stage 2: Runtime
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Harden pip against flaky networks (the big wheels were timing out mid-build).
ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5 \
    PIP_NO_CACHE_DIR=1

# Install runtime system dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# SECURITY: Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser

# Upgrade vulnerable Python packages in system Python
RUN pip install --no-cache-dir "wheel>=0.46.2" "jaraco.context>=6.1.0"

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy the rest of the application
COPY --chown=appuser:appuser . .

# Create necessary directories
RUN mkdir -p Phishy_Bizz logs data/ingestion && chown -R appuser:appuser /app

# Setup startup script
RUN chmod +x start.sh

USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH=/opt/venv/bin:$PATH

# Add healthcheck. /health is a cheap liveness probe that returns 200 while the
# API process is up (it reports DB status in the body without failing), so a
# transient DB outage does NOT flap the container — only a dead API does.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# API only (public ingress is nginx :8088 → /app)
EXPOSE 8000

# API + Yahoo stream monitor (Signal Deck served by FastAPI /app)
CMD ["./start.sh"]
