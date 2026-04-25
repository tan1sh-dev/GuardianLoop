FROM gcc:13

# ASan and UBSan ship with gcc; no extra package install required.
# Unprivileged runner user. /tmp is mounted as tmpfs at runtime.
RUN useradd -u 1000 -m runner
USER runner
WORKDIR /home/runner

# Actual command is provided by docker_runner: ["bash", "/sandbox/run.sh"]
CMD ["g++", "--version"]
