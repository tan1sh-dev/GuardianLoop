FROM python:3.11-slim

# Install system dependencies, including docker CLI just in case (though we use python SDK, it's handy) and semgrep requires some basics
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install python dependencies first to cache them
COPY requirements.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.txt semgrep

# Copy the rest of the application
COPY . .

# Install the application as a package
RUN pip install --no-cache-dir -e .

# Expose ports for Web UI / API
EXPOSE 8080 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run the application (assuming we want to run the web UI)
CMD ["uvicorn", "guardianloop.web.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
