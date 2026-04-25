"""
Docker sandbox runner.

Runs the patched source file inside a locked-down container with:
  --network=none --read-only --tmpfs /tmp --memory=512m --cpus=1
  --cap-drop=ALL --security-opt=no-new-privileges

The runner script's exit code tells us whether the exploit still reproduced.
Sync-only (the docker SDK is sync); agents call this via asyncio.to_thread.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

from guardianloop.sandbox.harness import (
    build_exploit_input,
    cpp_runner_script,
    python_runner_script,
)
from guardianloop.state import Finding

EXPLOIT_REPRODUCED_EXIT_CODE = 42


def _write_workdir(workdir: Path, language: str, patched_code: str, finding: Finding) -> None:
    if language == "python":
        (workdir / "target.py").write_text(patched_code, encoding="utf-8")
        (workdir / "run.sh").write_text(python_runner_script(), encoding="utf-8")
    else:
        (workdir / "target.cpp").write_text(patched_code, encoding="utf-8")
        (workdir / "run.sh").write_text(cpp_runner_script(), encoding="utf-8")
    (workdir / "exploit_input").write_text(build_exploit_input(finding), encoding="utf-8")


def run_exploit_in_sandbox(
    *,
    language: str,
    image: str,
    patched_code: str,
    finding: Finding,
    timeout: int,
) -> dict[str, Any]:
    """Run the patched code inside a sandboxed container and decide whether the exploit still works."""
    # Imported lazily so the module can still be imported in environments without Docker.
    import docker
    from docker.errors import APIError, DockerException, ImageNotFound

    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        return {
            "exploit_reproduced": False,
            "stdout": "",
            "stderr": f"Docker daemon not available: {e}",
            "exit_code": -1,
            "duration": 0.0,
        }

    with tempfile.TemporaryDirectory(prefix="guardianloop-") as tdir:
        workdir = Path(tdir)
        _write_workdir(workdir, language, patched_code, finding)

        start = time.monotonic()
        container = None
        stdout = ""
        stderr = ""
        exit_code = -1
        try:
            container = client.containers.run(
                image=image,
                command=["bash", "/sandbox/run.sh"],
                volumes={str(workdir): {"bind": "/sandbox", "mode": "ro"}},
                network_mode="none",
                read_only=True,
                tmpfs={"/tmp": "rw,size=128m,mode=1777"},
                mem_limit="512m",
                nano_cpus=1_000_000_000,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                detach=True,
                stdout=True,
                stderr=True,
            )
        except ImageNotFound:
            return {
                "exploit_reproduced": False,
                "stdout": "",
                "stderr": (
                    f"Sandbox image not found: {image}. Run `make docker-build`."
                ),
                "exit_code": -1,
                "duration": time.monotonic() - start,
            }
        except APIError as e:
            return {
                "exploit_reproduced": False,
                "stdout": "",
                "stderr": f"Docker API error: {e}",
                "exit_code": -1,
                "duration": time.monotonic() - start,
            }

        try:
            result = container.wait(timeout=timeout)
            exit_code = int(result.get("StatusCode", -1))
        except Exception as e:
            stderr = f"sandbox timeout or wait error: {e}\n"
            try:
                container.kill()
            except Exception:
                pass
        finally:
            try:
                stdout = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr = (
                    stderr
                    + container.logs(stdout=False, stderr=True).decode(
                        "utf-8", errors="replace"
                    )
                )
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass

        duration = time.monotonic() - start
        reproduced = exit_code == EXPLOIT_REPRODUCED_EXIT_CODE
        return {
            "exploit_reproduced": reproduced,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration": duration,
        }
