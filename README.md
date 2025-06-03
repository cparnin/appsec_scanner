# AppSec AI Scanner

An appsec security scanner that combines industry-standard security tools with OpenAI-generated remediation suggestions.

## Quick Start

### For PR Scanning
1. Copy `.github/workflows/appsec-pr-comment.yml` to your target repository
2. Set `OPENAI_API_KEY` in your repository secrets
3. Open a PR - the scanner will automatically comment with findings and AI fixes

### For Local Scanning
```bash
# Clone and setup
git clone https://github.com/cparnin/appsec_scanner
cd appsec_scanner
pip install -r requirements.txt

# Configure (copy env.example to .env and add your OpenAI key)
cp env.example .env
# Edit .env to add OPENAI_API_KEY=your_key_here

# Scan a repository
python src/cli.py --repo /path/to/target/repo --scan all --output outputs
```

##  Scanner Tools

- **Semgrep**: Static Application Security Testing (SAST)
- **Gitleaks**: Secret detection in git history  
- **Trivy**: Software Composition Analysis (dependency vulnerabilities)
- **OpenAI**: AI-generated remediation suggestions for each finding

##  Business Impact

The scanner provides concrete ROI metrics:
- **Time Savings**: Reduces developer research from 15 min to 3 min per issue
- **Cost Calculation**: Uses $150/hour security engineer rate
- **AI Coverage**: Typically achieves 95%+ AI suggestion coverage
- **Executive Reports**: Professional summaries for leadership/clients

##  Output Files

- `pr-findings.txt` - GitHub PR comment (critical + secrets only)
- `report.html` - Detailed technical report for developers
- `executive-summary.md` - Professional report for leadership
- `slack-executive-summary.txt` - Team communication format
- `outputs/raw/` - Raw scanner outputs (JSON format)

##  Configuration Options

```bash
# Scanner selection
--scan semgrep          # SAST only
--scan gitleaks         # Secrets only  
--scan sca             # Dependencies only
--scan all             # All scanners (default)

# AI configuration
--ai-batch-size 10     # Findings per API call (cost control)
--no-ai               # Skip AI suggestions (testing/cost control)

# Output control
--output /path/to/dir  # Custom output directory
```

##  Understanding the Output

### PR Comments (GitHub)
- **Focus**: Critical and secret findings only (avoid developer overwhelm)
- **Format**: Business metrics + specific AI fixes
- **Typical Count**: 10-50 findings from hundreds scanned

### Full Reports (HTML)
- **Focus**: All findings with severity-based filtering
- **Format**: Sortable table with detailed technical information
- **Use Case**: Developer deep-dive and comprehensive security review

### Executive Summaries
- **Focus**: Business impact and ROI calculations
- **Format**: Professional markdown suitable for leadership
- **Metrics**: Time saved, cost impact, security posture improvement


##  Integration Examples

### GitHub Actions (Recommended)
```yaml
# Copy .github/workflows/appsec-pr-comment.yml to target repo
# Set OPENAI_API_KEY in repository secrets
# Scanner runs automatically on PRs and pushes
```

### CI/CD Pipeline Integration
```bash
# In your existing pipeline:
git clone https://github.com/cparnin/appsec_scanner scanner
cd scanner
pip install -r requirements.txt
python src/cli.py --repo ../target-repo --scan all --output ../security-reports
```

### Scheduled Security Audits
```bash
# Weekly comprehensive scans
python src/cli.py --repo /path/to/main/branch --scan all --output weekly-audit-$(date +%Y%m%d)
```

## 🤝 Contributing

1. **Adding New Scanners**: Implement in `src/scanners/` following existing patterns
2. **AI Prompt Tuning**: Modify prompts in `src/ai/remediation.py`  
3. **Report Formats**: Extend templates in `src/reporting/templates/`
4. **Business Metrics**: Adjust calculations in `src/cli.py` main function

## 📄 License

MIT License - See LICENSE file for details

---

*Powered by ImagineX DevSecOps Guild*
