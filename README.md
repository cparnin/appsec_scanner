🔐 AppSec AI Scanner
An automated security scanning tool that integrates:

✅ Semgrep for static code analysis

✅ Gitleaks for secrets detection

🤖 OpenAI (GPT-4o) for AI-powered remediation suggestions

📄 Generates an HTML report and posts actionable comments on pull requests

🚀 Quickstart (Local Development)
bash
Copy
Edit
# Set up a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy the environment variable template and add your OpenAI API key
cp .env.example .env
Run the Scanner
bash
Copy
Edit
# Replace '../target-repo/' with the path to your target repository
python cli.py --repo ../target-repo/ --scan all
🛠 Project Structure
graphql
Copy
Edit
appsec_scanner/
├── cli.py                   # Main entry point for the scanner
├── scanner/
│   ├── semgrep.py           # Handles Semgrep static analysis
│   ├── gitleaks.py          # Handles Gitleaks secrets detection
│   ├── ai.py                # Interfaces with OpenAI for remediation suggestions
│   ├── report.py            # Generates HTML reports and PR comments
│   └── templates/
│       └── report.html.j2   # Jinja2 template for the HTML report
├── pr-findings.txt          # Markdown summary used for PR comments
├── .env.example             # Template for environment variables
├── requirements.txt         # Python dependencies
└── reports/                 # Output directory for generated reports
🔑 Environment Variables
Create a .env file in the root directory with the following content:

env
Copy
Edit
OPENAI_API_KEY=your_openai_api_key_here
Ensure this file is not committed to version control.

💬 GitHub Pull Request Integration
To enable automated scanning and commenting on pull requests, add the following GitHub Action to your target repository (e.g., juice-shop-fork) at .github/workflows/appsec-pr-comment.yml:

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
      - name: 📥 Checkout Code
        uses: actions/checkout@v4

      - name: 🐍 Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: 3.11

      - name: 📦 Install Semgrep & Dependencies
        run: |
          curl -sL https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-amd64 -o semgrep
          chmod +x semgrep && sudo mv semgrep /usr/local/bin/
          pip install openai requests jinja2 python-dotenv

      - name: 🧪 Run AppSec Scanner
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python cli.py --repo . --scan all

      - name: 💬 Comment on PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-findings.txt
Ensure you add your OpenAI API key as a secret in your repository settings under Settings > Secrets > Actions with the name OPENAI_API_KEY.

👥 DevSecOps Guild Setup
Clone the repository internally.

Each team member should create their own .env file using the .env.example template.

Add the OPENAI_API_KEY as a GitHub secret in any target repository.

Open pull requests to trigger the scan and AI-generated comments.

🧠 What Happens When You Open a PR on juice-shop-fork?
GitHub Action Triggers: The workflow runs on PR creation or updates.

Scanning:

Semgrep analyzes the code for static analysis issues.

Gitleaks scans for secrets in the codebase.

AI Remediation:

Findings are sent to OpenAI's GPT-4o for remediation suggestions.

Reporting:

A pr-findings.txt file is generated and posted as a PR comment.

A report.html file is created for detailed review.

🧹 Code Comments for Team Collaboration
To enhance readability and maintainability, comprehensive comments have been added to key Python files in your project. Here's an example for cli.py:

python
Copy
Edit
# cli.py

import argparse
from scanner import semgrep, gitleaks, ai, report

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Run AppSec AI Scanner")
    parser.add_argument("--repo", required=True, help="Path to the target repository")
    parser.add_argument("--scan", choices=["semgrep", "gitleaks", "all"], default="all", help="Specify which scans to run")
    args = parser.parse_args()

    # Run Semgrep scan
    if args.scan in ["semgrep", "all"]:
        semgrep_results = semgrep.run(args.repo)
    else:
        semgrep_results = []

    # Run Gitleaks scan
    if args.scan in ["gitleaks", "all"]:
        gitleaks_results = gitleaks.run(args.repo)
    else:
        gitleaks_results = []

    # Combine results
    findings = semgrep_results + gitleaks_results

    # Generate AI remediation suggestions
    ai_remediations = ai.generate(findings)

    # Generate HTML report
    report.generate_html(findings, ai_remediations)

    # Generate PR findings text
    report.generate_pr_findings(findings, ai_remediations)

if __name__ == "__main__":
    main()
Similar comments have been added to ai.py, report.py, and other relevant files to facilitate understanding and collaboration among team members.

📫 Questions?
For any questions or contributions, please contact @cparnin.
