FROM python:3.11-slim

# SECURITY: Create a non-root user
RUN groupadd -r secuser && useradd -r -g secuser -u 1001 secuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /sec
COPY --chown=secuser:secuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy security testing tools
COPY --chown=secuser:secuser tools/ /sec/tools/

# Set up data and logs directories
RUN mkdir -p /sec/data /sec/logs && chown -R secuser:secuser /sec

# Set environment variables
ENV PYTHONPATH=/sec
ENV ENVIRONMENT=hackbook
ENV SECURITY_LEVEL=testing

USER secuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)"

# Run security test suite
CMD ["python", "tools/test_suite.py"] 