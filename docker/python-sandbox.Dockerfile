FROM python:3.11-slim

# Minimal tools. The runner script is bind-mounted from /sandbox at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged runner user. /tmp is mounted as tmpfs at runtime.
RUN useradd -u 1000 -m runner
USER runner
WORKDIR /home/runner

# Actual command is provided by docker_runner: ["bash", "/sandbox/run.sh"]
CMD ["python3", "--version"]
