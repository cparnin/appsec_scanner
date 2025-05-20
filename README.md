# AppSec AI Scanner

Automated security scanning that integrates:

- Semgrep for static analysis  
- Gitleaks for secrets detection  
- OpenAI GPT-4o for AI-powered remediation  
- Generates PR comments and an HTML report

---

## 🔧 Quickstart (Local)

```bash
git clone https://github.com/cparnin/appsec_scanner.git
cd appsec_scanner

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
Set your .env:

env
Copy
Edit
OPENAI_API_KEY=your_openai_key_here
Run the scanner:

bash
Copy
Edit
python cli.py --repo ../your-code-repo/ --scan all
📁 Project Layout
Copy
Edit
.
├── cli.py
├── scanner/
│   ├── ai.py
│   ├── gitleaks.py
│   ├── semgrep.py
│   ├── report.py
│   └── templates/
│       └── report.html.j2
├── reports/
├── pr-findings.txt
├── requirements.txt
└── .env.example
🚀 GitHub PR Integration
Add this file to .github/workflows/appsec-pr-comment.yml in your target repo (like juice-shop-fork):

yaml
Copy
Edit
name: AppSec PR Scan

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

      - name: Install scanner & deps
        run: |
          curl -sL https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-amd64 -o semgrep
          chmod +x semgrep && sudo mv semgrep /usr/local/bin/
          pip install openai requests jinja2 python-dotenv

      - name: Run scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python cli.py --repo . --scan all

      - name: Comment PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-findings.txt
Then go to Settings > Secrets > Actions in GitHub and add:

ini
Copy
Edit
OPENAI_API_KEY=sk-...
👥 DevSecOps Guild Setup
Clone this repo

Create a .env file from .env.example

Use your own OpenAI API key

Run locally or use PR integration

Good targets: Juice Shop, DVWA, or your own codebases

What Happens on PRs?
Semgrep + Gitleaks run

GPT-4o suggests fixes

pr-findings.txt is posted as a PR comment

report.html is generated

Questions?
Owner: @cparnin

Pull requests welcome.
