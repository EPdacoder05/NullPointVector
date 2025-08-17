FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    hydra \
    burpsuite \
    metasploit-framework \
    aircrack-ng \
    wireshark \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy security testing tools
COPY tools/ /app/tools/

# Set up data and logs directories
RUN mkdir -p /data /logs

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=hackbook
ENV SECURITY_LEVEL=testing

# Run security test suite
CMD ["python", "tools/test_suite.py"] 