#!/usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

import argparse
import os
import json
from pathlib import Path
import logging
import webbrowser

from scanners.semgrep import run_semgrep  # Semgrep SAST scanner
from scanners.gitleaks import run_gitleaks  # Gitleaks secrets scanner
from scanners.sca import run_sca_scan  # SCA (dependency) scanner (stub for now)
from reporting.html import generate_html_report  # Report generator
from ai.remediation import batch_suggest_remediation  # Import the consolidated AI remediation function

import requests
import time

# Configure logging for the CLI
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

def main():
    """
    Main CLI entry point. Parses arguments, runs selected scanners, batches AI suggestions,
    and writes results to report files.
    """
    parser = argparse.ArgumentParser(description="Run Semgrep, Gitleaks, and SCA with AI remediation (batched, cheap!)")
    parser.add_argument("--repo", required=True, help="Path to the repo to scan")
    parser.add_argument("--scan", choices=["semgrep", "gitleaks", "sca", "all"], default="all")
    parser.add_argument("--output", default="../outputs", help="Directory to store reports")
    parser.add_argument("--ai-batch-size", type=int, default=10, help="How many findings per OpenAI call (default: 10)")
    args = parser.parse_args()

    repo_path = args.repo
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(exist_ok=True)

    results = {}

    # Add emoji terminal output for scan progress and completion
    print("🕵️‍♂️ AppSec Scanner starting...")
    if args.scan in ["semgrep", "all"]:
        print("🔍 Running Semgrep scan...")
        results["semgrep"] = run_semgrep(repo_path)

    if args.scan in ["gitleaks", "all"]:
        print("🔍 Running Gitleaks scan...")
        results["gitleaks"] = run_gitleaks(repo_path)

    # if args.scan in ["sca", "all"]:
    #     print("🛡️ Running SCA scan...")
    #     results["sca"] = run_sca_scan(repo_path)

    print("🤖 Generating AI remediation suggestions...")
    for tool, findings in results.items():
        if findings:
            batch_suggest_remediation(findings, batch_size=args.ai_batch_size)

    print("📝 Writing findings to pr-findings.txt...")
    # Write findings to PR-safe text file for GitHub Action comment
    emoji_map = {
        'critical': '🚨',
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢',
        'info': 'ℹ️',
        'secret': '🔑',
        'key': '🔑',
        'token': '🔑',
        'sca': '🛡️',
        'default': '❗',
    }
    def get_emoji(finding, tool):
        # Try severity first
        sev = (finding.get('extra', {}).get('severity') or finding.get('severity', '')).lower()
        tags = finding.get('Tags', []) + finding.get('tags', [])
        desc = finding.get('description', '').lower()
        if tool == 'gitleaks' or any(t in ['secret', 'key', 'token'] for t in tags) or 'secret' in desc or 'token' in desc or 'key' in desc:
            return emoji_map.get('secret')
        if sev in emoji_map:
            return emoji_map[sev]
        if tool == 'sca':
            return emoji_map['sca']
        return emoji_map['default']

    summary_lines = []
    for tool, findings in results.items():
        summary_lines.append(f"## {tool.capitalize()} Findings\n")
        if not findings:
            summary_lines.append("_No issues found._\n")
            continue
        for f in findings:
            emoji = get_emoji(f, tool)
            msg = f.get("extra", {}).get("message") or f.get("description", "No message")
            file_path = f.get("path") or f.get("file", "unknown file")
            line = f.get("start", {}).get("line") or f.get("line", "?")
            ai_fix = f.get("ai_remediation", "N/A")
            # Handle SCA-specific fields
            if tool == "sca":
                vuln_id = f.get("vulnerability_id", "")
                severity = f.get("severity", "UNKNOWN")
                fixed_versions = f.get("fixed_versions", [])
                fix_info = f" | Severity: {severity}"
                if vuln_id:
                    fix_info += f" | Vuln ID: {vuln_id}"
                if fixed_versions:
                    fix_info += f" | Fixed in: {', '.join(fixed_versions[:3])}"
                summary_lines.append(f"{emoji} **{msg}**{fix_info} in `{file_path}:{line}`\n  - 💡 *{ai_fix}*")
            else:
                summary_lines.append(f"{emoji} **{msg}** in `{file_path}:{line}`\n  - 💡 *{ai_fix}*")
        summary_lines.append("")  # Add space

    with open(output_dir / "pr-findings.txt", "w") as f:
        f.write("\n".join(summary_lines))

    print("📝 Generating HTML report...")
    generate_html_report(results, output_dir)

    print("🎉 Scan complete! Findings saved to pr-findings.txt and HTML report.")

if __name__ == "__main__":
    main()
