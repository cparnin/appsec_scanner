# 🔐 AppSec AI Scanner

An automated security scanning tool that integrates:

- ✅ **Semgrep** for static code analysis  
- ✅ **Gitleaks** for secrets detection  
- 🤖 **OpenAI GPT-4o** for AI-powered remediation suggestions  
- 📄 Generates an HTML report and PR comment with fixes  

---

## 🚀 Quickstart

### 1. Clone & Setup

```bash
git clone https://github.com/cparnin/appsec_scanner.git
cd appsec_scanner

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
Update your .env file:

env
Copy
Edit
OPENAI_API_KEY=your_openai_api_key_here
2. Run Locally
bash
Copy
Edit
python cli.py --repo ../your-repo/ --scan all
This generates:

pr-findings.txt – used for PR comments

reports/report.html – visual report

🛠 Project Structure
graphql
Copy
Edit
.
├── cli.py                  # Main CLI entry point
├── scanner/                # All scanning logic
│   ├── semgrep.py
│   ├── gitleaks.py
│   ├── ai.py
│   ├── report.py
│   └── templates/
│       └── report.html.j2
├── reports/                # Output reports
├── pr-findings.txt         # Summary posted in PRs
├── requirements.txt
└── .env.example            # API key template
🔑 GitHub Actions Integration
To scan PRs automatically, create this workflow in your target repo (e.g. juice-shop-fork):

.github/workflows/appsec-pr-comment.yml

yaml
Copy
Edit
name: AppSec LLM Scanner

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

      - name: Install tools
        run: |
          curl -sL https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-amd64 -o semgrep
          chmod +x semgrep && sudo mv semgrep /usr/local/bin/
          pip install openai requests jinja2 python-dotenv

      - name: Run scanner
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python cli.py --repo . --scan all

      - name: PR comment
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-findings.txt
Then in GitHub > Settings > Secrets > Actions, add:

ini
Copy
Edit
OPENAI_API_KEY = sk-...
👥 Team Setup (DevSecOps Guild)
Clone this repo

Set up .env with an OpenAI key (use .env.example)

Run locally or use the GitHub workflow

Works great with vulnerable repos like Juice Shop or DVWA

✅ What Happens on PR
When someone opens a pull request:

🛡 Semgrep and Gitleaks scan the code

🧠 GPT-4o suggests secure fixes

🗒 PR comment is posted with issues + AI remediation

📊 HTML report is generated for reviewers

🤝 Contribute
Pull requests welcome. Make security better for everyone.

Maintainer: @cparnin
