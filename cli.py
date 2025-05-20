import argparse
from scanner.semgrep import run_semgrep
from scanner.gitleaks import run_gitleaks
from scanner.sca import run_syft_sbom, run_trivy_scan
from scanner.ai import suggest_remediation
from scanner.report import generate_html_report

def main():
    parser = argparse.ArgumentParser(description="AppSec AI Remediation Tool")
    parser.add_argument("--repo", required=True, help="Path to repo")
    parser.add_argument("--output", default="reports", help="Report directory")
    parser.add_argument("--scan", choices=["semgrep", "gitleaks", "sca", "all"], default="all")
    args = parser.parse_args()

    repo = args.repo
    outdir = args.output

    results = {}
    if args.scan in ["semgrep", "all"]:
        results['semgrep'] = run_semgrep(repo, outdir)
    if args.scan in ["gitleaks", "all"]:
        results['gitleaks'] = run_gitleaks(repo, outdir)
    if args.scan in ["sca", "all"]:
        sbom_path = run_syft_sbom(repo, outdir)
        results['sca'] = run_trivy_scan(sbom_path, outdir)

    # AI remediation suggestions (just an example)
    for tool, findings in results.items():
        if findings:
            for finding in findings:
                finding["ai_fix"] = suggest_remediation(finding)

    generate_html_report(results, outdir)
    print(f"\nAll done! See results in: {outdir}")

if __name__ == "__main__":
    main()
