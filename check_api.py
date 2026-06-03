import urllib.request
import urllib.parse
import json
import time

SERVER_URL = "http://localhost:8080"

def make_request(path, method="GET", data=None):
    url = f"{SERVER_URL}{path}"
    headers = {"Content-Type": "application/json"}
    
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"Error calling {method} {url}: {e}")
        return None

def main():
    print(f"Checking GuardianLoop server at {SERVER_URL}...")
    
    # 1. Test connection by listing runs
    runs = make_request("/api/runs")
    if runs is None:
        print("[-] Could not connect to the server. Make sure the server is running!")
        return
    print(f"[+] Connected successfully. Current runs on server: {len(runs)}")

    # 2. Trigger the built-in demo scan
    print("[*] Triggering demo scan...")
    scan_resp = make_request("/api/scan/demo", method="POST")
    if not scan_resp or "run_id" not in scan_resp:
        print("[-] Failed to start the scan.")
        return
        
    run_id = scan_resp["run_id"]
    print(f"[+] Scan started. Run ID: {run_id}")

    # 3. Poll status until complete
    while True:
        # We can fetch the list of runs to see the status of our run
        runs_list = make_request("/api/runs") or []
        our_run = next((r for r in runs_list if r["id"] == run_id), None)
        
        if not our_run:
            print("[-] Run not found in active list. Retrying...")
            time.sleep(2)
            continue
            
        status = our_run.get("status", "pending")
        findings = our_run.get("findings", 0)
        patched = our_run.get("patched", 0)
        
        print(f"[*] Status: {status.upper()} | Findings: {findings} | Patches: {patched}")
        
        if status in ("complete", "failed"):
            break
            
        time.sleep(3)

    # 4. Show final results
    if status == "complete":
        print("\n[+] Scan pipeline completed successfully!")
        detail = make_request(f"/api/runs/{run_id}")
        if detail:
            findings_list = detail.get("enriched_findings", [])
            print(f"\nFound {len(findings_list)} vulnerabilities:")
            for idx, ef in enumerate(findings_list):
                f = ef.get("finding", {})
                print(f"  {idx + 1}. {f.get('cwe_id', 'unknown')} in {f.get('file_path')} (line {f.get('line_start')})")
                print(f"     Severity: {f.get('severity')} | Message: {f.get('message')}")
    else:
        print("\n[-] Scan pipeline failed.")

if __name__ == "__main__":
    main()
