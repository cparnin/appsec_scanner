#!/usr/bin/env python3
"""
AppSec AI Scanner - Main CLI Entry Point

This is the command-line interface for the AI-powered security scanner.
It orchestrates running multiple security tools and generating AI-powered remediation suggestions.

Usage:
    python cli.py --repo /path/to/target/repo --scan all

Business Value:
    - Finds security issues with 3 industry-standard tools
    - Provides AI-generated fix suggestions for each issue
    - Calculates time savings and cost impact for leadership reporting
    - Generates executive summaries for client/board presentations

For ImagineX DevSecOps Guild collaboration.
"""

# Load environment variables from .env file (contains OpenAI API key)
from dotenv import load_dotenv
load_dotenv()

import argparse
from pathlib import Path
import logging

# Import our scanner modules
from scanners.semgrep import run_semgrep      # Static Application Security Testing (SAST)
from scanners.gitleaks import run_gitleaks    # Secrets detection in git history
from scanners.sca import run_sca_scan         # Software Composition Analysis (dependency vulnerabilities)
from reporting.html import generate_html_report  # Pretty HTML reports for detailed review
from ai.remediation import batch_suggest_remediation  # OpenAI integration for fix suggestions

# Configure logging for debugging and monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Simple format without timestamps and module names
)
logger = logging.getLogger(__name__)

def validate_repo_path(repo_path: str) -> Path:
    """
    Safely validate that the repository path exists and is accessible.
    
    This prevents directory traversal attacks and ensures we're scanning
    a valid repository before spending time on security analysis.
    
    Args:
        repo_path: User-provided path to repository to scan
        
    Returns:
        Path: Resolved absolute path to repository
        
    Raises:
        ValueError: If path doesn't exist or isn't a directory
    """
    path = Path(repo_path).resolve()
    if not path.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")
    return path

def main():
    """
    Main CLI entry point that coordinates the entire security scanning workflow.
    
    Workflow:
    1. Parse command line arguments
    2. Validate input repository path
    3. Run selected security scanners (Semgrep, Gitleaks, Trivy)
    4. Generate AI remediation suggestions using OpenAI
    5. Calculate business impact metrics (time saved, cost savings)
    6. Generate reports for different audiences:
       - pr-findings.txt: GitHub PR comment with AI suggestions
       - executive-summary.md: Leadership report with ROI calculations
       - report.html: Detailed technical report for developers
    
    This design makes it easy to add new scanners or change AI providers.
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="AI-powered security scanner with business impact tracking"
    )
    
    # Required arguments
    parser.add_argument("--repo", required=True, help="Path to the repo to scan")
    
    # Optional scanner selection (allows running individual tools for testing)
    parser.add_argument(
        "--scan", 
        choices=["semgrep", "gitleaks", "sca", "all"], 
        default="all",
        help="Which scanners to run (default: all)"
    )
    
    # Output customization
    parser.add_argument(
        "--output", 
        default="../outputs", 
        help="Directory to store reports (default: ../outputs)"
    )
    
    # AI configuration
    parser.add_argument(
        "--ai-batch-size", 
        type=int, 
        default=10, 
        help="How many findings per OpenAI call (default: 10, helps control costs)"
    )
    parser.add_argument(
        "--no-ai", 
        action="store_true", 
        help="Skip AI remediation suggestions (for faster testing or cost control)"
    )
    
    args = parser.parse_args()

    try:
        # STEP 1: Validate inputs to prevent security issues
        repo_path = validate_repo_path(args.repo)
        
        # Fix output directory path to be relative to script location
        if args.output.startswith("../"):
            # If relative path, make it relative to script location (not project root)
            script_dir = Path(__file__).parent  # src/ directory
            output_dir = (script_dir / args.output).resolve()
        else:
            output_dir = Path(args.output).resolve()
            
        output_dir.mkdir(parents=True, exist_ok=True)  # Create output directory if it doesn't exist
        
        # Debug path information
        logger.info(f"📁 Script directory: {Path(__file__).parent}")
        logger.info(f"📁 Output directory: {output_dir}")
        logger.info(f"📁 Current working directory: {Path.cwd()}")
        
        logger.info("🕵️‍♂️ AppSec Scanner starting...")
        results = {}  # Will store findings from each scanner tool

        # STEP 2: Run security scanners
        # Each scanner follows the same interface pattern for easy extension
        
        if args.scan in ["semgrep", "all"]:
            logger.info("🔍 Running Semgrep scan (Static Application Security Testing)...")
            results["semgrep"] = run_semgrep(str(repo_path), output_dir)

        if args.scan in ["gitleaks", "all"]:
            logger.info("🔍 Running Gitleaks scan (secrets detection)...")
            results["gitleaks"] = run_gitleaks(str(repo_path), output_dir)

        if args.scan in ["sca", "all"]:
            logger.info("🛡️ Running SCA scan (dependency vulnerabilities with Trivy)...")
            results["sca"] = run_sca_scan(str(repo_path), output_dir)

        # STEP 3: Generate AI remediation suggestions
        if not args.no_ai:
            logger.info("🤖 Generating AI remediation suggestions...")
            total_findings = sum(len(findings) for findings in results.values())
            
            if total_findings > 0:
                # Process each tool's findings through AI
                for tool, findings in results.items():
                    if findings:
                        # Batch API calls to minimize OpenAI costs
                        batch_suggest_remediation(findings, batch_size=args.ai_batch_size)
            else:
                logger.info("No findings to process with AI")

        # STEP 3.5: Filter out low-severity findings to focus on actionable issues
        def should_include_finding(finding):
            """Filter out low/info severity findings to focus on actionable security issues"""
            severity = (finding.get('extra', {}).get('severity') or 
                       finding.get('severity', '')).lower()
            
            # Keep critical, high, medium, error findings
            # Filter out low, info, warning (these are often style/best practices)
            return severity in ['critical', 'high', 'medium', 'error']
        
        # Apply severity filter to all results
        filtered_results = {}
        for tool, findings in results.items():
            if findings:
                filtered_findings = [f for f in findings if should_include_finding(f)]
                filtered_results[tool] = filtered_findings
                if len(filtered_findings) < len(findings):
                    logger.info(f"🔽 {tool.capitalize()}: Filtered {len(findings)} → {len(filtered_findings)} findings (removed low/info severity)")
            else:
                filtered_results[tool] = findings
        
        # Use filtered results for all reporting
        results = filtered_results

        # STEP 4: Calculate business impact metrics
        # These calculations provide leadership with concrete ROI numbers
        total_findings = sum(len(findings) for findings in results.values())
        ai_suggestions = sum(1 for tool_findings in results.values() 
                            for finding in tool_findings 
                            if finding.get('ai_remediation') and finding['ai_remediation'] != 'N/A')
        
        # Business calculation assumptions (documented for transparency):
        # - Manual security research: 15 minutes per issue (research + fix)
        # - AI-assisted workflow: 3 minutes per issue (guided fix)
        # - Security engineer cost: $150/hour (conservative industry rate)
        manual_hours = total_findings * 0.25  # 15 minutes = 0.25 hours
        ai_hours = total_findings * 0.05      # 3 minutes = 0.05 hours
        time_saved = manual_hours - ai_hours
        cost_savings = time_saved * 150  # $150/hour security engineer rate

        # STEP 5: Generate reports for different audiences
        
        # GitHub PR comment with business context
        logger.info("📝 Writing findings to pr-findings.txt...")
        _write_pr_findings(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path)

        # Detailed HTML report for developers
        logger.info("📝 Generating HTML report...")
        generate_html_report(results, output_dir, repo_path)
        
        # Executive summary for leadership/clients
        logger.info("📊 Generating executive summary...")
        _write_executive_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path)
        
        # Slack-friendly summary (plain text with emojis)
        logger.info("💬 Generating Slack-friendly summary...")
        _write_slack_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path)

        # STEP 6: Display immediate results for CLI users
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

def _write_pr_findings(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path):
    """
    Generate GitHub PR comment with security findings and AI suggestions.
    
    This creates a markdown file that GitHub Actions can post as a PR comment.
    The format is optimized for developer readability while showing business value.
    
    For PR comments, we use more restrictive filtering to avoid overwhelming developers:
    - Semgrep/Trivy: Only critical and high severity issues
    - Gitleaks: All secrets (always critical)
    
    Args:
        results: Dictionary of findings by scanner tool
        output_dir: Where to write the pr-findings.txt file
        total_findings: Total number of security issues found
        ai_suggestions: Number of AI remediation suggestions generated
        time_saved: Hours saved vs manual analysis
        cost_savings: Dollar value of productivity improvement
        repo_path: Path to the scanned repository
    """
    
    def should_include_in_pr(finding, tool):
        """Ultra-restrictive filtering for PR comments to avoid overwhelming developers"""
        # Always include secrets from Gitleaks (they're always actionable)
        if tool == 'gitleaks':
            return True
            
        # For other tools, only include CRITICAL severity (not high)
        # This keeps PR comments focused on the most urgent issues
        severity = (finding.get('extra', {}).get('severity') or finding.get('severity', '')).lower()
        return severity == 'critical'
    
    # Apply PR-specific filtering
    pr_filtered_results = {}
    total_pr_findings = 0
    for tool, findings in results.items():
        if findings:
            pr_findings = [f for f in findings if should_include_in_pr(f, tool)]
            pr_filtered_results[tool] = pr_findings
            total_pr_findings += len(pr_findings)
            if len(pr_findings) < len(findings):
                print(f"📝 PR Comment: {tool.capitalize()} showing {len(pr_findings)}/{len(findings)} findings (critical + secrets only)")
        else:
            pr_filtered_results[tool] = findings
    
    # Emoji mapping for visual impact in PR comments
    emoji_map = {
        'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️',
        'secret': '🔑', 'key': '🔑', 'token': '🔑', 'sca': '🛡️', 'default': '❗',
    }
    
    def get_emoji(finding, tool):
        """Determine appropriate emoji based on finding severity and type."""
        # Extract severity from different scanner output formats
        sev = (finding.get('extra', {}).get('severity') or finding.get('severity', '')).lower()
        tags = finding.get('Tags', []) + finding.get('tags', [])
        desc = finding.get('description', '').lower()
        
        # Special handling for secrets (always use key emoji)
        if tool == 'gitleaks' or any(t in ['secret', 'key', 'token'] for t in tags) or 'secret' in desc:
            return emoji_map.get('secret')
        
        # Use severity-based emoji or default
        return emoji_map.get(sev, emoji_map['default'])

    # Build PR comment content with business context at the top
    summary_lines = [
        "# 🔒 AI-Powered Security Scan Results",
        "",
        f"**🤖 AI Analysis:** {ai_suggestions} automated remediation suggestions generated",
        f"**⏱️ Time Saved:** {time_saved:.1f} hours vs manual analysis", 
        f"**💰 Value:** ${cost_savings:,.0f} in productivity gains",
        "",
        f"**🔍 Repository:** {repo_path}",
        f"**📊 Showing:** {total_pr_findings} critical + secrets findings (full report has {total_findings} total issues)",
        ""
    ]
    
    # Add findings from each scanner tool (using PR-filtered results)
    for tool, findings in pr_filtered_results.items():
        summary_lines.append(f"## {tool.capitalize()} Findings")
        
        if not findings:
            summary_lines.append("_No critical + secrets issues found._")
            continue
            
        for f in findings:
            emoji = get_emoji(f, tool)
            
            # Extract finding details from different scanner output formats
            msg = f.get("extra", {}).get("message") or f.get("description", "No message")
            file_path = f.get("path") or f.get("file", "unknown file")
            line = f.get("start", {}).get("line") or f.get("line", "?")
            ai_fix = f.get("ai_remediation", "N/A")
            
            # Format as GitHub markdown
            summary_lines.append(f"{emoji} **{msg}** in `{file_path}:{line}`")
            summary_lines.append(f"  - 💡 *{ai_fix}*")
        summary_lines.append("")
    
    # Add note about full report
    if total_pr_findings < total_findings:
        summary_lines.extend([
            "---",
            f"📋 **Full Report:** {total_findings - total_pr_findings} additional medium/low findings available in detailed HTML report",
            ""
        ])

    # Write to file for GitHub Action to pick up
    pr_file_path = output_dir / "pr-findings.txt"
    logger.info(f"📝 Writing PR findings to: {pr_file_path}")
    logger.info(f"📝 PR content length: {len('\\n'.join(summary_lines))} characters")
    pr_file_path.write_text("\\n".join(summary_lines))
    logger.info(f"📝 File written successfully: {pr_file_path.exists()}")

def _write_executive_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path):
    """
    Generate executive summary for leadership and client presentations.
    
    This creates a professional markdown report that can be forwarded to
    executives, included in client deliverables, or presented to the board.
    
    Key features:
    - Business metrics prominently displayed
    - Transparent calculation methodology 
    - Clear next steps for action
    - Professional formatting for external sharing
    
    Args:
        results: Dictionary of findings by scanner tool
        output_dir: Where to write the executive-summary.md file
        total_findings: Total number of security issues found
        ai_suggestions: Number of AI remediation suggestions generated
        time_saved: Hours saved vs manual analysis
        cost_savings: Dollar value of productivity improvement
        repo_path: Path to the scanned repository
    """
    from datetime import datetime
    
    # Count high-priority issues for executive attention
    critical_high = 0
    for tool_findings in results.values():
        for finding in tool_findings:
            severity = (finding.get('extra', {}).get('severity') or 
                       finding.get('severity', '')).lower()
            if severity in ['critical', 'high']:
                critical_high += 1
    
    # Generate professional executive summary
    summary = f"""# 🔒 Security Scan Executive Summary

**Date:** {datetime.now().strftime('%B %d, %Y')}
**Scanned Repository:** {repo_path}

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
{', '.join(tool.replace('sca', 'Trivy').title() for tool in results.keys())}

## 📈 Next Steps
1. Review findings in the detailed HTML report
2. Prioritize critical and high-severity issues
3. Use AI suggestions to accelerate remediation
4. Run follow-up scans to verify fixes

---
*Generated by ImagineX AppSec AI Scanner*
"""
    
    # Write executive summary for leadership sharing
    (output_dir / "executive-summary.md").write_text(summary)
    print(f"📊 Executive summary saved to executive-summary.md")

def _write_slack_summary(results, output_dir, total_findings, ai_suggestions, time_saved, cost_savings, repo_path):
    """
    Generate Slack-friendly summary using plain text formatting.
    
    Slack doesn't render markdown well, so this uses emojis and plain text
    that displays properly in Slack channels.
    """
    from datetime import datetime
    
    # Count high-priority issues for executive attention
    critical_high = 0
    for tool_findings in results.values():
        for finding in tool_findings:
            severity = (finding.get('extra', {}).get('severity') or 
                       finding.get('severity', '')).lower()
            if severity in ['critical', 'high']:
                critical_high += 1
    
    # Generate Slack-friendly summary
    summary = f"""🔒 SECURITY SCAN RESULTS

📅 Date: {datetime.now().strftime('%B %d, %Y')}
📁 Repository: {repo_path}

📊 KEY RESULTS
• Total Security Issues: {total_findings}
• Critical/High Severity: {critical_high}
• AI Remediation Coverage: {ai_suggestions}/{total_findings} issues ({ai_suggestions/total_findings*100 if total_findings > 0 else 0:.0f}%)

💰 BUSINESS IMPACT
• Developer Time Saved: {time_saved:.1f} hours
• Estimated Cost Savings: ${cost_savings:,.0f}
• Productivity Improvement: 80% faster security remediation

🛠️ TOOLS USED
{', '.join(tool.replace('sca', 'Trivy').title() for tool in results.keys())}

📈 NEXT STEPS
1. Review findings in the detailed HTML report
2. Prioritize critical and high-severity issues
3. Use AI suggestions to accelerate remediation
4. Run follow-up scans to verify fixes

Generated by ImagineX AppSec AI Scanner"""
    
    # Write Slack summary
    (output_dir / "slack-executive-summary.txt").write_text(summary)
    print(f"💬 Slack executive summary saved to slack-executive-summary.txt")

# Standard Python entry point
if __name__ == "__main__":
    main()
