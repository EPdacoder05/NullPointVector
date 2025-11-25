FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install CI-specific packages
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    flake8 \
    mypy \
    safety \
    bandit

# Copy pipeline code
COPY pipelines/ /app/pipelines/

# Set up artifacts directory
RUN mkdir -p /artifacts

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=hackbook
ENV CI_MODE=testing

# Run pipeline runner
CMD ["python", "pipelines/runner.py"] 