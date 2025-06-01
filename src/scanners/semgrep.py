import subprocess
import json
from pathlib import Path
import logging
import webbrowser

logger = logging.getLogger(__name__)

def run_semgrep(repo_path):
    """
    Run Semgrep SAST scanner on the given repository path.
    Returns a list of findings in standardized format.
    """
    try:
        out_dir = Path("../outputs/raw")
        out_dir.mkdir(parents=True, exist_ok=True)
        output_file = out_dir / "semgrep.json"
        # Run Semgrep with auto config and output JSON results
        result = subprocess.run([
            "semgrep", "--config", "auto", "--json", "--output", str(output_file), repo_path
        ], capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):
            logger.warning(f"Semgrep returned code {result.returncode}")
            logger.warning(f"stdout: {result.stdout}")
            logger.warning(f"stderr: {result.stderr}")
        # Parse and return findings from the JSON output
        with open(output_file) as f:
            results = json.load(f).get("results", [])
        webbrowser.open(str(out_dir / "report.html"))
        return results
    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out after 5 minutes")
        return []
    except Exception as e:
        logger.error(f"Error running Semgrep: {e}")
        return []