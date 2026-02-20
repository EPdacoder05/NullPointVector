FROM python:3.11-slim

# SECURITY: Create a non-root user
RUN groupadd -r labuser && useradd -r -g labuser -u 1001 labuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /lab
COPY --chown=labuser:labuser requirements.txt .
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
COPY --chown=labuser:labuser pipelines/ /lab/pipelines/

# Set environment variables
ENV PYTHONPATH=/lab
ENV ENVIRONMENT=hackbook
ENV CI_MODE=testing

USER labuser

# Healthcheck
HEALTHCHECK CMD python -c "import sys; sys.exit(0)"

# Run pipeline runner
CMD ["python", "pipelines/runner.py"] 