# syntax=docker/dockerfile:1
# Multi-stage: builder has gcc + pip; runtime is non-root, no compiler, no pip.

FROM python:3.11-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Base-image pip/setuptools/wheel + vendored jaraco.context carry HIGH CVEs.
RUN pip install --upgrade \
        "pip>=26.1.2" \
        "setuptools>=83.0.0" \
        "wheel>=0.46.2" \
        "jaraco.context>=6.1.0"

# CPU-only torch first so requirements.txt does not pull the CUDA wheel.
# Must be >=2.3 for numpy 2 / sentence-transformers.
RUN pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install -r requirements.txt \
    && pip install \
        "scikit-learn==1.9.0" \
        "numpy==2.4.6" \
        "scipy==1.17.1" \
        "joblib==1.5.3" \
        "cryptography==48.0.1"

# python-jose native backend leftover (CVE-2024-23342, no upstream fix).
# PyJWT[crypto] does not need these; uninstall if a transitive still pulled them.
RUN pip uninstall -y ecdsa rsa pyasn1 || true

# Runtime must not ship pip/setuptools/wheel (HIGH CVEs + extra attack surface).
RUN pip uninstall -y pip setuptools wheel || true


FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        curl \
        libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 --shell /usr/sbin/nologin appuser

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser . .

RUN mkdir -p Phishy_Bizz logs data/ingestion data/dlq \
    && chmod +x start.sh \
    && chown -R appuser:appuser Phishy_Bizz logs data

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["./start.sh"]
