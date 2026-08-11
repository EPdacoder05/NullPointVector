# Use Python 3.11 slim image
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Harden pip against flaky networks (the big wheels were timing out mid-build).
ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch FIRST instead of the default CUDA build (~2GB). These
# containers do CPU inference, so the bundled NVIDIA/CUDA payload is dead weight:
# it bloats the image, slows builds + cold-starts, and makes the bare `torch>=2.0`
# resolve fragile. Installing the CPU wheel here satisfies the requirements pin,
# so the next layer skips torch entirely. Identical CPU speed.
# NOTE: must be >=2.3 — earlier torch predates NumPy 2 support and breaks under
# our pinned numpy==2.4.6 (transformers/sentence-transformers fail to import).
RUN pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu

# Copy requirements first
COPY requirements.txt .

# Install Python dependencies (torch already satisfied above → not re-pulled)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir fastapi uvicorn
# API hardening deps (explicit layer so they are always present even if the
# requirements layer above is cache-hit from an older build).
RUN pip install --no-cache-dir "python-multipart>=0.0.6" "python-jose[cryptography]>=3.3" "prometheus-client>=0.19" "redis>=5.0" "gunicorn>=21.0" "argon2-cffi>=23.1" "jinja2>=3.1"
# Pin the ML stack so model artifacts load deterministically (no train/serve
# version skew → no silent per-boot retrain). These are stamped into every
# artifact by the detectors; regenerate artifacts when bumping these.
RUN pip install --no-cache-dir "scikit-learn==1.9.0" "numpy==2.4.6" "scipy==1.17.1" "joblib==1.5.3"
# Pin cryptography last so it wins over any transitive upgrade. The latest wheel
# SIGILLs on some ARM hosts; 43.0.1 is verified-good on x86_64 + aarch64.
RUN pip install --no-cache-dir "cryptography==43.0.1"

# SECURITY: create the non-root user BEFORE copying so we can set ownership via
# COPY --chown. A separate `chown -R /app` would rewrite every file's metadata
# into a brand-new layer — that alone DUPLICATED the whole ~5.8GB /app tree and
# was a primary cause of the bloated image. --chown avoids that entirely.
RUN useradd -m appuser

# Copy the application (already owned by appuser; build context is slimmed by
# .dockerignore — the 4.2GB data/ingestion corpus is NOT baked in, it is mounted
# as a volume at runtime).
COPY --chown=appuser:appuser . .

# Runtime dirs (volumes mount over data/* at runtime). Chown only these new dirs
# — never `-R` over the whole tree — so we don't duplicate the app layer.
RUN mkdir -p Phishy_Bizz logs data/ingestion data/dlq \
    && chmod +x start.sh \
    && chown -R appuser:appuser Phishy_Bizz logs data

USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Add healthcheck. /health is a cheap liveness probe that returns 200 while the
# API process is up (it reports DB status in the body without failing), so a
# transient DB outage does NOT flap the container — only a dead API does.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# API only (public ingress is nginx :8088 → /app)
EXPOSE 8000

# API + Yahoo stream monitor (Signal Deck served by FastAPI /app)
CMD ["./start.sh"]
