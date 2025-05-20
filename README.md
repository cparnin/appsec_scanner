# AppSec AI Scanner

This tool automates scanning of pull requests using:

- Semgrep for static code analysis
- Gitleaks for secrets detection
- OpenAI (GPT-4o-mini) for AI-powered remediation suggestions
- Generates HTML report + PR comment with actionable fixes

---

## Quickstart (Local Dev)

```bash
# Set up local Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Add your OpenAI API key
cp .env.example .env
Run the scanner
bash
Copy
Edit
python cli.py --repo ../target-repo/ --scan all
🛠 Project Structure
graphql
Copy
Edit
.
├── cli.py                   # Main entry point
├── scanner/
│   ├── semgrep.py           # Semgrep SAST scan logic
│   ├── gitleaks.py          # Gitleaks secrets scan logic
│   ├── ai.py                # Batched OpenAI remediation logic
│   ├── report.py            # HTML report generator
│   └── templates/
│       └── report.html.j2   # Jinja2 template for reports
├── pr-findings.txt          # Markdown summary for PR comments
├── .env.example             # Environment variable template
├── requirements.txt
└── reports/                 # Output files (HTML, JSON)
🔑 .env Format
env
Copy
Edit
OPENAI_API_KEY=sk-...
GitHub PR Integration
Add this GitHub Action to your target repo (e.g., juice-shop-fork) at:

.github/workflows/appsec-pr-comment.yml

yaml
Copy
Edit
name: AppSec LLM Scanner – PR Comment

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: 3.11

      - name: Install scanner + dependencies
        run: |
          curl -sL https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-amd64 -o semgrep
          chmod +x semgrep && sudo mv semgrep /usr/local/bin/
          pip install openai requests python-dotenv jinja2

      - name: Run AppSec Scanner
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python cli.py --repo . --scan all

      - name: Comment on PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-findings.txt
DevSecOps Guild Setup
Share the repo internally

Each team member creates their own .env from the template

Add OPENAI_API_KEY as GitHub secret in any target repo

Open PRs to trigger scan + AI comment

What Happens When You Open a PR on juice-shop-fork?
GitHub triggers your Action

Semgrep scans the PR code (Python, JS, etc.)

Gitleaks scans for secrets in current files

Each finding is bundled and sent to GPT-4o (batched) for remediation advice

A comment is posted on the PR with all findings and suggested fixes

Bonus: report.html gets generated for any audits or dev review

Collaboration Tips
Each scanner component is modular and replaceable

Can swap OpenAI for local LLM in ai.py

Add a license checker (e.g., Syft + Trivy) for Phase 2

📫 Questions?
Ping @cparnin

🔐