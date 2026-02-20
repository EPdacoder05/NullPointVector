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

# Stage 2: Runtime
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime system dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# SECURITY: Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser

WORKDIR /app

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

# Expose ports
EXPOSE 8050 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import sys; sys.exit(0)"

# Run the startup script (Runs both API and UI)
CMD ["./start.sh"]