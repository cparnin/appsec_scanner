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

