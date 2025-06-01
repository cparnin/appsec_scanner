import subprocess
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def run_gitleaks(repo_path):
    """
    Run Gitleaks secrets scanner on the given repository path.
    Returns a list of findings in standardized format.
    """
    try:
        out_dir = Path("../outputs/raw")
        out_dir.mkdir(parents=True, exist_ok=True)
        output_file = out_dir / "gitleaks.json"
        
        # Run Gitleaks with custom config and output JSON results
        config_path = Path(__file__).parent.parent.parent / "configs" / ".gitleaks.toml"
        cmd = [
            "gitleaks", "detect",
            "--source", repo_path,
            "--config", str(config_path),
            "--report-format", "json",
            "--report-path", str(output_file),
            "--no-banner",
            "--exit-code", "0"  # Don't fail CI on findings
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Gitleaks exits with code 1 when it finds secrets, which is normal
        if result.returncode not in (0, 1):
            logger.error(f"Gitleaks failed with exit code {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
            return []
        
        # Check if output file exists and parse results
        if output_file.exists():
            # Handle potential UTF-8 decode errors gracefully
            with open(output_file, encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            
            if not content:
                logger.info("Gitleaks found no secrets (empty output)")
                return []
            
            results = json.loads(content)
            if isinstance(results, list):
                logger.info(f"Gitleaks found {len(results)} potential secrets")
                return results
            else:
                logger.warning("Unexpected Gitleaks output format")
                return []
        else:
            logger.info("Gitleaks found no secrets (no output file)")
            return []
    
    except subprocess.TimeoutExpired:
        logger.error("Gitleaks scan timed out after 2 minutes")
        return []
    except Exception as e:
        logger.error(f"Error running gitleaks: {e}")
        return []
