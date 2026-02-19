FROM nvidia/cuda:12.2.0-cudnn8-runtime-ubuntu22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
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
COPY training/ /app/training/

# Set up data and models directories
RUN mkdir -p /data /models

# SECURITY: Create a non-root user
RUN useradd -m mluser && chown -R mluser:mluser /app /data /models
USER mluser

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=hackbook
ENV GPU_ENABLED=true

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3 -c "import os; import torch; assert os.path.exists('/app/training/pipeline.py'), 'Pipeline script missing'; assert torch.__version__, 'Torch not available'" || exit 1

# Run training pipeline
CMD ["python3", "training/pipeline.py"] 