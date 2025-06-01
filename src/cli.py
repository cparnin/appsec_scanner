#!/usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

import argparse
from pathlib import Path
import logging

from scanners.semgrep import run_semgrep
from scanners.gitleaks import run_gitleaks
from scanners.sca import run_sca_scan
from reporting.html import generate_html_report
from ai.remediation import batch_suggest_remediation

# Configure logging for the CLI
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_repo_path(repo_path: str) -> Path:
    """Validate and resolve repository path safely."""
    path = Path(repo_path).resolve()
    if not path.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")
    return path

def main():
    """
    Main CLI entry point. Parses arguments, runs selected scanners, batches AI suggestions,
    and writes results to report files with business metrics.
    """
    parser = argparse.ArgumentParser(
        description="AI-powered security scanner with business impact tracking"
    )
    parser.add_argument("--repo", required=True, help="Path to the repo to scan")
    parser.add_argument(
        "--scan", 
        choices=["semgrep", "gitleaks", "sca", "all"], 
        default="all",
        help="Which scanners to run"
    )
    parser.add_argument(
        "--output", 
        default="../outputs", 
        help="Directory to store reports"
    )
    parser.add_argument(
        "--ai-batch-size", 
        type=int, 
        default=10, 
        help="How many findings per OpenAI call (default: 10)"
    )
    parser.add_argument(
        "--no-ai", 
        action="store_true", 
        help="Skip AI remediation suggestions"
    )
    
    args = parser.parse_args()

    try:
        # Validate inputs
        repo_path = validate_repo_path(args.repo)
        output_dir = Path(args.output).resolve()
        output_dir.mkdir(exist_ok=True)
        
        logger.info("🕵️‍♂️ AppSec Scanner starting...")
        results = {}

        # Run security scans
        if args.scan in ["semgrep", "all"]:
            logger.info("🔍 Running Semgrep scan...")
            results["semgrep"] = run_semgrep(str(repo_path))

        if args.scan in ["gitleaks", "all"]:
            logger.info("🔍 Running Gitleaks scan...")
            results["gitleaks"] = run_gitleaks(str(repo_path))

        if args.scan in ["sca", "all"]:
            logger.info("🛡️ Running SCA scan...")
            results["sca"] = run_sca_scan(str(repo_path))

        # Generate AI remediation suggestions
        if not args.no_ai:
            logger.info("🤖 Generating AI remediation suggestions...")
            total_findings = sum(len(findings) for findings in results.values())
            if total_findings > 0:
                for tool, findings in results.items():
                    if findings:
                        batch_suggest_remediation(findings, batch_size=args.ai_batch_size)
            else:
                logger.info("No findings to process with AI")

        # Calculate business metrics
        total_findings = sum(len(findings) for findings in results.values())
        ai_suggestions = sum(1 for tool_findings in results.values() 
                            for finding in tool_findings 
                            if finding.get('ai_remediation') and finding['ai_remediation'] != 'N/A')
        
        # Simple calculation: 15 min manual research vs 3 min with AI guidance
        manual_hours = total_findings * 0.25  # 15 min each
        ai_hours = total_findings * 0.05      # 3 min each  
        time_saved = manual_hours - ai_hours
        cost_savings = time_saved * 150  # $150/hour

        # Generate reports
        logger.info("📝 Writing findings to pr-findings.txt...")
        _write_pr_findings(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings)

        logger.info("📝 Generating HTML report...")
        generate_html_report(results, output_dir)
        
        # Generate executive summary
        logger.info("📊 Generating executive summary...")
        _write_executive_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings)

        # Print summary for immediate visibility
        print("\n" + "="*60)
        print("🎉 SCAN COMPLETE - BUSINESS IMPACT SUMMARY")
        print("="*60)
        print(f"Total Issues Found: {total_findings}")
        print(f"AI Suggestions: {ai_suggestions} ({ai_suggestions/total_findings*100 if total_findings > 0 else 0:.0f}%)")
        print(f"Time Saved: {time_saved:.1f} hours")
        print(f"Cost Savings: ${cost_savings:,.0f}")
        print("="*60)

    except Exception as e:
        logger.error(f"Scanner failed: {e}")
        raise

def _write_pr_findings(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings):
    """Write findings to PR comment format with business context."""
    
    emoji_map = {
        'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️',
        'secret': '🔑', 'key': '🔑', 'token': '🔑', 'sca': '🛡️', 'default': '❗',
    }
    
    def get_emoji(finding, tool):
        sev = (finding.get('extra', {}).get('severity') or finding.get('severity', '')).lower()
        tags = finding.get('Tags', []) + finding.get('tags', [])
        desc = finding.get('description', '').lower()
        if tool == 'gitleaks' or any(t in ['secret', 'key', 'token'] for t in tags) or 'secret' in desc:
            return emoji_map.get('secret')
        return emoji_map.get(sev, emoji_map['default'])

    summary_lines = [
        "# 🔒 AI-Powered Security Scan Results",
        "",
        f"**🤖 AI Analysis:** {ai_suggestions} automated remediation suggestions generated",
        f"**⏱️ Time Saved:** {time_saved:.1f} hours vs manual analysis", 
        f"**💰 Value:** ${cost_savings:,.0f} in productivity gains",
        ""
    ]
    
    for tool, findings in results.items():
        summary_lines.append(f"## {tool.capitalize()} Findings")
        if not findings:
            summary_lines.append("_No issues found._")
            continue
        for f in findings:
            emoji = get_emoji(f, tool)
            msg = f.get("extra", {}).get("message") or f.get("description", "No message")
            file_path = f.get("path") or f.get("file", "unknown file")
            line = f.get("start", {}).get("line") or f.get("line", "?")
            ai_fix = f.get("ai_remediation", "N/A")
            
            summary_lines.append(f"{emoji} **{msg}** in `{file_path}:{line}`")
            summary_lines.append(f"  - 💡 *{ai_fix}*")
        summary_lines.append("")

    (output_dir / "pr-findings.txt").write_text("\n".join(summary_lines))

def _write_executive_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings):
    """Write a simple executive summary for leadership."""
    from datetime import datetime
    
    # Count critical/high severity issues
    critical_high = 0
    for tool_findings in results.values():
        for finding in tool_findings:
            severity = (finding.get('extra', {}).get('severity') or 
                       finding.get('severity', '')).lower()
            if severity in ['critical', 'high']:
                critical_high += 1
    
    summary = f"""# 🔒 Security Scan Executive Summary

**Date:** {datetime.now().strftime('%B %d, %Y')}
**Scanned Repository:** {len(results)} security tools used

## 📊 Key Results
- **Total Security Issues:** {total_findings}
- **Critical/High Severity:** {critical_high}
- **AI Remediation Coverage:** {ai_suggestions}/{total_findings} issues ({ai_suggestions/total_findings*100 if total_findings > 0 else 0:.0f}%)

## 💰 Business Impact
- **Developer Time Saved:** {time_saved:.1f} hours
- **Estimated Cost Savings:** ${cost_savings:,.0f}
- **Productivity Improvement:** 80% faster security remediation

## 🧮 Calculation Methodology
```
Manual Process (without AI):
• Time per issue: 15 minutes (research + fix)
• Total manual time: {total_findings} issues × 15 min = {total_findings * 15} minutes

AI-Enhanced Process:
• Time per issue: 3 minutes (guided fix)  
• Total AI time: {total_findings} issues × 3 min = {total_findings * 3} minutes

Time Savings:
• {total_findings * 15} - {total_findings * 3} = {(total_findings * 15) - (total_findings * 3)} minutes saved
• {time_saved:.1f} hours × $150/hour = ${cost_savings:,.0f} value
```

## 🤖 AI Enhancement
Our AI-powered scanner automatically generates specific remediation guidance for each security issue, reducing the time developers spend researching fixes from 15 minutes to 3 minutes per issue.

## 🛠️ Tools Used
{', '.join(tool.title() for tool in results.keys())}

## 📈 Next Steps
1. Review findings in the detailed HTML report
2. Prioritize critical and high-severity issues
3. Use AI suggestions to accelerate remediation
4. Run follow-up scans to verify fixes

---
*Generated by ImagineX AppSec AI Scanner*
"""
    
    (output_dir / "executive-summary.md").write_text(summary)
    print(f"📊 Executive summary saved to executive-summary.md")

if __name__ == "__main__":
    main()
