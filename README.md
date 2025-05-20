# AppSec AI Scanner

An automated security scanner that:

- Runs Semgrep for static code analysis
- Runs Gitleaks for secrets detection
- Uses OpenAI GPT-4o for AI-powered remediation
- Generates an HTML report and a pull request comment

---

## Quickstart (Local)

```bash
git clone https://github.com/cparnin/appsec_scanner.git
cd appsec_scanner

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add your API key:

```env
OPENAI_API_KEY=sk-...
```

Then run it:

```bash
python cli.py --repo ../your-target-repo --scan all
```

---

## Project Structure

```
.
├── cli.py
├── scanner/
│   ├── semgrep.py
│   ├── gitleaks.py
│   ├── ai.py
│   ├── report.py
│   └── templates/
│       └── report.html.j2
├── reports/
├── pr-findings.txt
├── requirements.txt
└── .env.example
```

---

## GitHub PR Automation

In your target repo (like juice-shop-fork), create this file:

`.github/workflows/appsec-pr-comment.yml`

```yaml
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

      - name: Comment on PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-findings.txt
```

Also go to `Settings > Secrets > Actions` in that repo and add:

```
OPENAI_API_KEY = sk-...
```

---

## Team Setup (DevSecOps Guild)

- Clone this repo
- Create `.env` using the `.env.example` template
- Add OpenAI key
- Run manually or via GitHub Action
- Test it on DVWA, Juice Shop, or your apps

---

## What Happens When a PR Is Opened?

1. GitHub Action triggers
2. Semgrep and Gitleaks run
3. GPT-4o-mini suggests fixes
4. A PR comment is posted
5. HTML report is generated

---

## Maintainer

[@cparnin](https://github.com/cparnin)

Pull requests welcome.
