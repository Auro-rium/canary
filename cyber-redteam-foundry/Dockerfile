FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifest first for better layer caching
COPY pyproject.toml ./
COPY src ./src
COPY configs ./configs
COPY prompts ./prompts

# Pre-install CPU torch to avoid downloading the 4 GB CUDA wheel
RUN pip install --no-cache-dir \
    "torch>=2.0.0" \
    --index-url https://download.pytorch.org/whl/cpu

# Install the project (torch requirement already satisfied above)
RUN pip install --no-cache-dir -e .

ENV PYTHONPATH=/app:/app/src

EXPOSE 8001

CMD ["uvicorn", "cyberredteam.api:app", "--host", "0.0.0.0", "--port", "8001"]
