# Contributing to GuardianLoop

Welcome to the GuardianLoop project! We appreciate your interest in making this autonomous security pipeline better. There are two primary areas where contributions are highly encouraged: adding new static analysis rules and enhancing the core agent logic.

## 1. Adding New Semgrep Rules

GuardianLoop relies on Semgrep to power the **Scout** agent, which identifies vulnerabilities across the codebase. You can easily extend the platform's detection capabilities by adding custom rules.

### How to add rules:
1. Navigate to the `rules/` directory in the root of the project.
2. Create a new `.yaml` file or edit an existing one.
3. Define your Semgrep rule pattern. If you're new to writing rules, check out the [Semgrep Documentation](https://semgrep.dev/docs/writing-rules/).
4. The Scout agent dynamically reads all `.yaml` files in the `rules/` directory. Your new rules will automatically be picked up on the very next scan without any code changes or restarts required!

## 2. Contributing to Agent Logic

GuardianLoop's intelligence is powered by LangGraph, forming a multi-agent system consisting of the Scout, Classifier, Fixer, and Red-Team. 

### Development Workflow:
1. **Locate the Logic**: The core agent logic and prompts are located in the `src/guardianloop/agents/` directory. The state graph definition is located in `src/guardianloop/graph.py`.
2. **Setup**: Ensure you have created a `.env` file based on `.env.example` with the necessary API keys (such as `GOOGLE_API_KEY`).
3. **Local Testing**: We recommend using the provided Docker Compose stack for development to ensure the sandbox environments are available.
   ```bash
   docker compose build
   docker compose up -d web
   ```
4. **Submit a Pull Request**: Once you've tested your changes, push your branch and open a Pull Request! Please ensure your code is formatted and includes descriptions of the logic changes made.

---

Thank you for contributing to GuardianLoop!
