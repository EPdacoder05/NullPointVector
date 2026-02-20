FROM nvidia/cuda:12.1.0-cudnn8-runtime-ubuntu22.04

# SECURITY: Create a non-root user
RUN groupadd -r mluser && useradd -r -g mluser -u 1001 mluser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /ml
COPY --chown=mluser:mluser requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Install ML-specific packages
RUN pip3 install --no-cache-dir \
    torch \
    torchvision \
    torchaudio \
    transformers \
    scikit-learn \
    pandas \
    numpy \
    matplotlib \
    seaborn

# Copy training code
COPY --chown=mluser:mluser training/ /ml/training/

# Set environment variables
ENV PYTHONPATH=/ml
ENV ENVIRONMENT=hackbook
ENV GPU_ENABLED=true

USER mluser

# Healthcheck
HEALTHCHECK CMD python3 -c "import sys; sys.exit(0)"

# Run training pipeline
CMD ["python3", "training/pipeline.py"] 