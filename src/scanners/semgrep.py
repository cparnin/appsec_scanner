import subprocess
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def run_semgrep(repo_path: str, output_dir: Path = None) -> list:
    """
    Run Semgrep SAST scanner on the given repository path.
    Returns a list of findings in standardized format.
    
    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)
    """
    try:
        # Use provided output_dir or default
        if output_dir is None:
            output_dir = Path("../outputs/raw")
        else:
            output_dir = output_dir / "raw"
            
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "semgrep.json"
        
        # Validate repo path exists
        repo_path_obj = Path(repo_path).resolve()
        if not repo_path_obj.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return []
        
        # Run Semgrep with auto config and output JSON results
        cmd = [
            "semgrep", 
            "--config", "auto", 
            "--json", 
            "--output", str(output_file), 
            str(repo_path_obj)
        ]
        
        logger.info(f"Running Semgrep scan on {repo_path}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode not in (0, 1):
            logger.warning(f"Semgrep returned code {result.returncode}")
            logger.warning(f"stdout: {result.stdout}")
            logger.warning(f"stderr: {result.stderr}")
        
        # Parse and return findings from the JSON output
        with open(output_file) as f:
            results = json.load(f).get("results", [])
        return results
            
    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out after 5 minutes")
        return []
    except Exception as e:
        logger.error(f"Error running Semgrep: {e}")
        return []