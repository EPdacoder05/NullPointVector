FROM nvidia/cuda:11.8.0-cudnn8-runtime-ubuntu20.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.9 \
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

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=hackbook
ENV GPU_ENABLED=true

# Run training pipeline
CMD ["python3", "training/pipeline.py"] 