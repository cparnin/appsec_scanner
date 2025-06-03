# AppSec AI Scanner

AI-powered security scanner that finds vulnerabilities and generates fix suggestions.

## Quick Start

**Local Scanning:**
```bash
git clone https://github.com/imaginexconsulting/appsec_scanner
cd appsec_scanner  
pip install -r requirements.txt
cp env.example .env
# Add your OPENAI_API_KEY to .env

python src/cli.py --repo /path/to/target/repo
```

**GitHub PR Scanning:**
1. Copy `.github/workflows/appsec-pr-comment.yml` to your repo
2. Add `OPENAI_API_KEY` to repository secrets
3. Open a PR - scanner comments automatically

## What It Does

- **Finds Security Issues**: Runs Semgrep, Gitleaks, and Trivy
- **AI Fix Suggestions**: OpenAI generates specific remediation code  
- **Business Metrics**: Calculates time/cost savings for leadership
- **Multiple Reports**: PR comments, HTML reports, executive summaries

## Outputs

- `pr-findings.txt` - GitHub PR comment
- `report.html` - Detailed technical report  
- `executive-summary.md` - Leadership summary
- `outputs/raw/` - Raw scanner data

## Options

```bash
--scan all|semgrep|gitleaks|sca  # Which scanners to run
--no-ai                          # Skip AI suggestions  
--output /custom/path            # Output directory
```

## For Guild Collaboration

**Ready for team collaboration!** Everything works locally and in GitHub Actions.

**Key Files:**
- `src/cli.py` - Main scanner logic
- `src/scanners/` - Individual tool integrations  
- `src/ai/remediation.py` - OpenAI integration

**Easy to extend:** Add new scanners in `src/scanners/` following existing patterns.

---
*Powered by ImagineX DevSecOps Guild*
