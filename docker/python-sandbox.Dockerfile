FROM python:3.11-slim

# Minimal tools. The runner script is bind-mounted from /sandbox at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install common libraries needed for testing/exploiting scripts
RUN pip install --no-cache-dir \
    pyyaml \
    requests \
    cryptography \
    bcrypt \
    jinja2 \
    pyjwt \
    pandas \
    numpy \
    httpx \
    flask \
    fastapi \
    uvicorn \
    pycryptodome \
    beautifulsoup4 \
    python-dotenv \
    openpyxl \
    asteval

# Unprivileged runner user. /tmp is mounted as tmpfs at runtime.
RUN useradd -u 1000 -m runner
USER runner
WORKDIR /home/runner

# Actual command is provided by docker_runner: ["bash", "/sandbox/run.sh"]
CMD ["python3", "--version"]
