FROM python:3.12-slim-bookworm

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

# SECURITY: Create a non-root user
RUN useradd -m ciuser && chown -R ciuser:ciuser /app /artifacts
USER ciuser

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=hackbook
ENV CI_MODE=testing

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

# Run pipeline runner
CMD ["python", "pipelines/runner.py"] 