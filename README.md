# AI Security Scanner

Automated security scanner that finds vulnerabilities and generates AI-powered fix suggestions.

## Quick Start

### Local Setup
```bash
git clone https://github.com/imaginexconsulting/appsec_scanner
cd appsec_scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Run Scanner
```bash
python src/cli.py --repo /path/to/target/repo
```

### GitHub PR Integration
1. Copy `.github/workflows/appsec-pr-comment.yml` to your target repo
2. Add `OPENAI_API_KEY` to repository secrets  
3. Open a PR -> scanner comments automatically

## What It Does

- **Security Scanning**: Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies)
- **AI Remediation**: Specific fix suggestions for each issue
- **Business Impact**: Time/cost savings calculations
- **Multiple Outputs**: PR comments, HTML reports, executive summaries

## Options

```bash
--scan all|semgrep|gitleaks|sca  # Choose scanners
--no-ai                          # Skip AI suggestions  
--output /path                   # Custom output directory
```

## Team Collaboration

### For Guild Members

**Prerequisites:**
- Python 3.8+
- OpenAI API key
- Your organization's GitHub access

**Adding New Scanners:**
1. Create `src/scanners/your_tool.py`
2. Follow existing patterns in `semgrep.py` or `gitleaks.py`
3. Add integration to `src/cli.py`
4. Test and document

### Key Files
- `src/cli.py` - Main orchestrator
- `src/scanners/` - Security tool integrations
- `src/ai/remediation.py` - OpenAI integration

### Outputs Generated
- `outputs/pr-findings.txt` - GitHub PR comment
- `outputs/report.html` - Technical details
- `outputs/executive-summary.md` - Leadership report
- `outputs/slack-executive-summary.txt` - Slack Summary

---
*Ready for ImagineX Guild collaboration*
