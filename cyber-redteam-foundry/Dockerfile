FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application source code first so pip can build the package
COPY . .

# Install project and dependencies
RUN pip install --no-cache-dir -e .

# Set python path to allow target_agent and cyberredteam to be found
ENV PYTHONPATH=/app:/app/src

# Expose ports
EXPOSE 8000
EXPOSE 9000

# Default command to run the backend API
CMD ["uvicorn", "cyberredteam.api:app", "--host", "0.0.0.0", "--port", "8000"]
