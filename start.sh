#!/bin/bash
set -e

echo "=========================================="
echo "    GuardianLoop Local Deployment         "
echo "=========================================="

# Check if Docker is installed and running
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is not installed or not in PATH."
    echo "Please install Docker Desktop and try again."
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is installed, but the daemon is not running."
    echo "Please start Docker Desktop, wait for it to initialize, and try again."
    exit 1
fi

# Ensure .env exists
if [ ! -f .env ]; then
    echo ".env file not found. Let's create one."
    read -p "Enter your Google Gemini API Key: " api_key
    if [ -z "$api_key" ]; then
        echo "API Key cannot be empty. Exiting."
        exit 1
    fi
    echo "GOOGLE_API_KEY=$api_key" > .env
    echo ".env file created successfully."
else
    echo ".env file found. Using existing API key."
fi

echo ""
echo "[1/3] Building the sandbox environments and main application..."
# We use docker compose build to build the web app and the two sandboxes
docker compose build

echo ""
echo "[2/3] Starting GuardianLoop..."
# Start only the web service, detached
docker compose up -d web

echo ""
echo "[3/3] GuardianLoop is running!"
echo "Access the Web Dashboard at: http://localhost:8080"
echo "To view logs, run: docker compose logs -f web"
echo "To stop, run: docker compose down"
