# AppSec AI Scanner

An AI-powered security scanner that delivers immediate business value:

- **3 Security Tools**: Semgrep (SAST), Gitleaks (secrets), Trivy (SCA)
- **AI Remediation**: OpenAI GPT-4o-mini provides specific fix guidance
- **Business Metrics**: Calculates time savings and cost impact
- **Executive Reports**: Leadership-ready summaries with transparent ROI
- **GitHub Integration**: Automated PR comments with AI suggestions

**Ready for demos and internal security automation.**

---

## 🚀 Quickstart (Local)

```bash
git clone https://github.com/cparnin/appsec_scanner.git
cd appsec_scanner

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
cp env.example .env
```

Edit `.env` and add your API key:

```env
OPENAI_API_KEY=sk-your-openai-api-key-here
```

Install external tools:
```bash
# Install Trivy (SCA scanning)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks (secrets scanning)  
curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_$(uname -m).tar.gz | tar -xz
sudo mv gitleaks /usr/local/bin/
```

Run the scanner:

```bash
cd src
python cli.py --repo ../your-target-repo --scan all
```

## 📊 Business Impact Example

```
🎉 SCAN COMPLETE - BUSINESS IMPACT SUMMARY
============================================================
Total Issues Found: 23
AI Suggestions: 23 (100%)
Time Saved: 4.6 hours
Cost Savings: $690
============================================================
```

---

## 📁 Project Structure

```
appsec_scanner/
├── src/
│   ├── cli.py                 # Main entry point
│   ├── scanners/
│   │   ├── semgrep.py        # SAST scanning
│   │   ├── gitleaks.py       # Secrets detection
│   │   └── sca.py            # Trivy SCA scanning
│   ├── ai/
│   │   └── remediation.py    # OpenAI integration
│   └── reporting/
│       ├── html.py           # HTML report generator
│       └── templates/
│           └── report.html   # Report template
├── outputs/                  # Generated reports
│   ├── pr-findings.txt      # GitHub PR comment
│   ├── executive-summary.md # Leadership report
│   ├── report.html         # Detailed HTML report
│   └── raw/                # Raw scanner outputs
├── configs/
│   └── .gitleaks.toml      # Gitleaks configuration
├── requirements.txt
├── env.example
└── README.md
```

---

## 🤖 GitHub PR Automation

Create this file in your target repository:

`.github/workflows/appsec-pr-comment.yml`

```yaml
name: AppSec PR Scan

on:
  pull_request:
    branches: [master]
  push:
    branches: [master]

jobs:
  AppSec_PR_Scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Python & Dependencies
        run: |
          pip install semgrep openai requests jinja2 python-dotenv
          semgrep --version

      - name: Install Gitleaks
        run: |
          curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_$(uname -m).tar.gz | tar -xz
          sudo mv gitleaks /usr/local/bin/

      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Run AppSec Scanner
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          cd src
          python cli.py --repo .. --scan all

      - name: Comment on PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: outputs/pr-findings.txt
        if: always()
```

Add your OpenAI API key to repository secrets:
`Settings > Secrets > Actions > OPENAI_API_KEY`

---

## 🎯 ImagineX Demo Script

1. **Show the command**: `python cli.py --repo ../client-repo --scan all`
2. **Highlight the output**: Time saved, cost savings, AI suggestions
3. **Show the executive summary**: Perfect for client leadership
4. **Demonstrate GitHub integration**: Automated PR security reviews

## 💰 Business Value Proposition

- **80% faster** security remediation vs manual research
- **$150/hour** security engineer time saved
- **Immediate ROI** on every scan
- **Client-ready** executive reporting
- **Scalable** across entire development teams

---

## 🛠️ Usage Options

```bash
# Scan with all tools
python cli.py --repo /path/to/repo --scan all

# Individual scanners
python cli.py --repo /path/to/repo --scan semgrep
python cli.py --repo /path/to/repo --scan gitleaks  
python cli.py --repo /path/to/repo --scan sca

# Skip AI suggestions (faster)
python cli.py --repo /path/to/repo --no-ai

# Custom output directory
python cli.py --repo /path/to/repo --output /custom/path
```

---

## 👥 Team Collaboration

Perfect for ImagineX Security Guild:
- **Modular design** - easy to add new scanners
- **Clear business metrics** - leadership visibility
- **Simple Python** - team can contribute easily
- **Transparent calculations** - math is visible and adjustable
- **Client-ready** - immediate demo value

---

## 📈 Roadmap

**Phase 1** ✅ (Current):
- Multi-tool security scanning
- AI remediation suggestions  
- Business impact tracking
- GitHub PR automation

**Phase 2** (Future):
- AWS Bedrock integration?
- Custom AI prompts
- Jira ticket creation
- Slack notifications
- Trend analysis dashboard

---

## 🤝 Contributing

This project is designed for ImagineX DevSecOps Guild collaboration:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/scanner-name`
3. Add your scanner following the existing pattern
4. Test with DSVW or vulnerable applications
5. Submit pull request

---

## 📞 Support

**Maintainer**: [@cparnin](https://github.com/cparnin)

**ImagineX Team**: Ready for demos, client pilots, and team contributions.

Pull requests welcome! 🚀
