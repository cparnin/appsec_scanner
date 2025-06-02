#!/usr/bin/env python3
"""
SCA (Software Composition Analysis) Scanner Skeleton

This module is a placeholder for future SCA integration (e.g., Trivy, Syft).
It is designed to scan dependencies for known vulnerabilities (SCA), but is not yet implemented.

TODO (Guild):
- Integrate Trivy or Syft for dependency scanning
- Normalize output to standard finding format
- Add tests and CLI integration
"""

import subprocess
import json
from pathlib import Path
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def run_sca_scan(repo_path: str, output_dir: Path = None) -> List[Dict[str, Any]]:
    """
    Run Trivy SCA (Software Composition Analysis) scanner on the given repository.
    Scans for dependency vulnerabilities in package files.
    Returns a list of findings in standardized format.
    """
    try:
        # Use provided output_dir or default
        if output_dir is None:
            out_dir = Path("../outputs/raw")
        else:
            out_dir = output_dir / "raw"
        
        out_dir.mkdir(parents=True, exist_ok=True)
        output_file = out_dir / "trivy-sca.json"
        
        # Validate repo path exists
        repo_path_obj = Path(repo_path).resolve()
        if not repo_path_obj.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return []
        
        # Check what dependency files exist to provide better feedback
        dep_files = []
        dep_patterns = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle"
        ]
        
        for pattern in dep_patterns:
            matches = list(repo_path_obj.rglob(pattern))
            dep_files.extend(matches)
        
        if dep_files:
            logger.info(f"Found dependency files: {[f.name for f in dep_files[:5]]}")
        else:
            logger.info("No common dependency files found - scanning filesystem anyway")
        
        # Run Trivy filesystem scan for vulnerabilities
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--output", str(output_file),
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            str(repo_path_obj)
        ]
        
        logger.info(f"Running Trivy SCA scan on {repo_path}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            logger.warning(f"Trivy returned code {result.returncode}")
            logger.warning(f"stderr: {result.stderr}")
            # Trivy may return non-zero even on successful scans with findings
        
        # Parse and return findings from the JSON output
        if output_file.exists():
            with open(output_file, encoding='utf-8') as f:
                data = json.load(f)
                
            # Transform Trivy output to standardized format
            standardized_findings = []
            results = data.get("Results", [])
            
            # Count what was scanned
            scanned_targets = len(results)
            total_vulnerabilities = 0
            
            for result in results:
                target = result.get("Target", "unknown")
                vulnerabilities = result.get("Vulnerabilities", [])
                total_vulnerabilities += len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    finding = {
                        "path": target,
                        "line": 1,  # Dependencies don't have specific lines
                        "description": f"{vuln.get('PkgName', 'Unknown')} {vuln.get('InstalledVersion', '')}: {vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown vulnerability'))}",
                        "severity": vuln.get("Severity", "UNKNOWN").lower(),
                        "vulnerability_id": vuln.get("VulnerabilityID", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "references": vuln.get("References", [])
                    }
                    standardized_findings.append(finding)
            
            if scanned_targets > 0 and total_vulnerabilities == 0:
                logger.info(f"Trivy scanned {scanned_targets} dependency files - no vulnerabilities found (dependencies are clean)")
            elif total_vulnerabilities > 0:
                logger.info(f"Trivy found {len(standardized_findings)} dependency vulnerabilities across {scanned_targets} files")
            else:
                logger.info("Trivy found no dependency files to scan")
                
            return standardized_findings
        else:
            logger.info("Trivy found no vulnerabilities (no output file)")
            return []
            
    except subprocess.TimeoutExpired:
        logger.error("Trivy scan timed out after 5 minutes")
        return []
    except FileNotFoundError:
        logger.error("Trivy not found. Please install Trivy: https://trivy.dev/getting-started/installation/")
        return []
    except Exception as e:
        logger.error(f"Error running Trivy SCA scan: {e}")
        return []
