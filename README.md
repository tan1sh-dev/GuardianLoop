# GuardianLoop

Autonomous multi-agent pipeline for detecting, patching, and adversarially verifying security vulnerabilities in C++ and Python code.

GuardianLoop uses a combination of static analysis (Semgrep) and Large Language Models (Gemini 2.5) to automatically find bugs, generate fixes, and test those fixes dynamically in a sandbox to ensure they are secure against exploits.

## Architecture

1. **Scout**: Runs Semgrep to detect static vulnerabilities across the codebase.
2. **Classifier**: Enriches the findings with CWE mapping and severity scores.
3. **Fixer**: Generates a patch for the vulnerable code using Gemini.
4. **Red-Team**: Attempts to write an exploit to bypass the fix inside a secure Docker sandbox. If the exploit works, it feeds the context back to the Fixer to refine the patch until it is fully secure.

## Prerequisites

- **Python 3.10+**
- **WSL (Ubuntu)**: Required if running on Windows, as the Semgrep binary relies on a Linux environment to execute.
- **Docker**: Required for the Red-Team agent to safely run and verify exploits in an isolated sandbox.
- **Google API Key**: Required for the Gemini model agents.

## Quickstart

### 1. Install Dependencies
Clone the repository and install the package locally:
```bash
git clone https://github.com/tan1sh-dev/GuardianLoop-Final.git
cd GuardianLoop-Final
pip install -e .
```

### 2. Configure Environment Variables
You need a Google Gemini API Key to power the agents.
```bash
export GOOGLE_API_KEY="your_gemini_api_key"
```
*(You can also place this in a `.env` file at the root of the project).*

### 3. Build Docker Sandboxes
Build the secure docker environments used by the Red-Team agent to test the exploits:
```bash
make docker-build
```

### 4. Run the Web Application
Start the unified FastAPI backend and React frontend:
```bash
uvicorn guardianloop.web.app:app --host 0.0.0.0 --port 8080
```

Once the server starts, open your browser and navigate to:
**http://localhost:8080**

From the dashboard, you can initiate live scans, view pipeline logs, and see the verified patched code side-by-side with the vulnerabilities!

## Logs and Artifacts

Every scan generates an isolated run folder under `./runs/<timestamp>/`. 
This folder contains detailed JSON summaries, markdown audit reports, and individual agent logs for full observability of the remediation loop.
