@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo     GuardianLoop Local Deployment         
echo ==========================================

:: Check if Docker is installed and running
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Docker is not installed or not in PATH.
    echo Please install Docker Desktop and try again.
    exit /b 1
)
docker info >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Docker is installed, but the daemon is not running.
    echo Please start Docker Desktop, wait for it to initialize, and try again.
    exit /b 1
)

:: Ensure .env exists
if not exist ".env" (
    echo .env file not found. Let's create one.
    set /p api_key="Enter your Google Gemini API Key: "
    if "!api_key!"=="" (
        echo API Key cannot be empty. Exiting.
        exit /b 1
    )
    echo GOOGLE_API_KEY=!api_key!> .env
    echo .env file created successfully.
) else (
    echo .env file found. Using existing API key.
)

echo.
echo [1/3] Building the sandbox environments and main application...
docker compose build

echo.
echo [2/3] Starting GuardianLoop...
docker compose up -d web

echo.
echo [3/3] GuardianLoop is running!
echo Access the Web Dashboard at: http://localhost:8080
echo To view logs, run: docker compose logs -f web
echo To stop, run: docker compose down
