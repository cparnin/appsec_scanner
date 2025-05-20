import subprocess
import json
from pathlib import Path

def run_gitleaks(repo_path):
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    output_file = out_dir / "gitleaks.json"
    subprocess.run([
        "gitleaks", "detect", "-s", repo_path, "--report-format", "json", "-r", str(output_file)
    ], check=True)
    with open(output_file) as f:
        results = json.load(f)
    return results