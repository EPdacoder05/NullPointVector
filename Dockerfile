# Use Python 3.11 slim image
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .

# Install Python dependencies (including API server and Dash)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install fastapi uvicorn dash plotly dash-bootstrap-components

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p Phishy_Bizz logs data/ingestion

# Setup startup script
COPY start.sh .
RUN chmod +x start.sh

# SECURITY: Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose ports
EXPOSE 8050 8000

# Run the startup script (Runs both API and UI)
CMD ["./start.sh"]