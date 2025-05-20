import argparse
import os
import json
from scanner.semgrep import run_semgrep
from scanner.gitleaks import run_gitleaks
from scanner.ai import suggest_remediation
from scanner.report import generate_html_report
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Run Semgrep and Gitleaks with AI remediation")
    parser.add_argument("--repo", required=True, help="Path to the repo to scan")
    parser.add_argument("--scan", choices=["semgrep", "gitleaks", "all"], default="all")
    parser.add_argument("--output", default="reports", help="Directory to store reports")
    args = parser.parse_args()

    repo_path = args.repo
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    results = {}

    if args.scan in ["semgrep", "all"]:
        results["semgrep"] = run_semgrep(repo_path)

    if args.scan in ["gitleaks", "all"]:
        results["gitleaks"] = run_gitleaks(repo_path)

    for tool, findings in results.items():
        for finding in findings:
            finding["ai_remediation"] = suggest_remediation(finding)

    # Write findings to PR-safe text file
    summary_lines = []
    for tool, findings in results.items():
        summary_lines.append(f"## {tool.capitalize()} Findings\n")
        if not findings:
            summary_lines.append("_No issues found._\n")
            continue
        for f in findings:
            msg = f.get("extra", {}).get("message") or f.get("description", "No message")
            file_path = f.get("path") or f.get("file", "unknown file")
            line = f.get("start", {}).get("line") or f.get("line", "?")
            ai_fix = f.get("ai_remediation", "N/A")
            summary_lines.append(f"- **{msg}** in `{file_path}:{line}`\n  - 💡 *{ai_fix}*")
        summary_lines.append("")  # Add space

    with open("pr-findings.txt", "w") as f:
        f.write("\n".join(summary_lines))

    # Optional: generate an HTML report for human reading
    generate_html_report(results, output_dir)

    print("✅ Scan complete. Findings saved to 'pr-findings.txt' and HTML report.")

if __name__ == "__main__":
    main()
