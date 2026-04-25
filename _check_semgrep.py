import json
import os
import subprocess

env = os.environ.copy()
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUTF8"] = "1"
env["SEMGREP_USE_OSEMGREP"] = "false"

p = subprocess.run(
    [
        "semgrep", "scan",
        "--config=p/default",
        "--json", "--metrics=off",
        "samples/demo_cwe121.cpp",
    ],
    capture_output=True,
    timeout=180,
    env=env,
)

with open("_check_semgrep_out.txt", "w", encoding="utf-8") as f:
    f.write(f"rc={p.returncode}\n")
    f.write("STDERR (first 1500):\n")
    f.write(p.stderr.decode("utf-8", errors="replace")[:1500])
    s = p.stdout.decode("utf-8", errors="replace")
    f.write("\n\nSTDOUT len: " + str(len(s)) + "\n")
    if s.strip().startswith("{"):
        try:
            d = json.loads(s)
            f.write(f"\nhits={len(d.get('results', []))}\n")
            for r in d.get("results", []):
                f.write(f"  {r['check_id']} -> CWE={r.get('extra',{}).get('metadata',{}).get('cwe')}\n")
        except Exception as e:
            f.write(f"\n\nJSON parse error: {e}\n")

print("done")
