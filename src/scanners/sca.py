#!/usr/bin/env python3
"""
SCA (Software Composition Analysis) Scanner

This module integrates Trivy for dependency scanning.
It can use pre-existing Trivy results from GitHub Actions or run Trivy locally.
"""

import subprocess
import json
import os
from pathlib import Path
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def run_sca_scan(repo_path: str, output_dir: Path = None) -> List[Dict[str, Any]]:
    """
    Run Trivy SCA (Software Composition Analysis) scanner on the given repository.
    First checks for existing Trivy results from GitHub Actions, then runs locally if needed.
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
        
        # Check if we already have Trivy results from GitHub Actions
        github_trivy_results = out_dir / "trivy-results.json"
        if github_trivy_results.exists():
            logger.info("Using existing Trivy results from GitHub Action")
            # Copy/rename to our expected filename for consistency
            import shutil
            shutil.copy2(github_trivy_results, output_file)
        else:
            # Run Trivy locally
            logger.info("Running Trivy scan locally")
            if not _run_trivy_scan(repo_path, output_file):
                return []
        
        # Parse and return findings from the JSON output
        return _parse_trivy_results(output_file)
            
    except Exception as e:
        logger.error(f"Error in SCA scan: {e}")
        return []

def _run_trivy_scan(repo_path: str, output_file: Path) -> bool:
    """Run Trivy scan locally and return True if successful."""
    try:
        # Validate repo path exists
        repo_path_obj = Path(repo_path).resolve()
        if not repo_path_obj.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return False
        
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
        
        # Get Trivy binary path from environment variable or use default
        trivy_bin = os.environ.get('TRIVY_BIN', 'trivy')
        
        # Run Trivy filesystem scan for vulnerabilities
        cmd = [
            trivy_bin, "fs",
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
        
        return True
        
    except subprocess.TimeoutExpired:
        logger.error("Trivy scan timed out after 5 minutes")
        return False
    except FileNotFoundError:
        logger.error("Trivy not found. Please install Trivy: https://trivy.dev/getting-started/installation/")
        return False
    except Exception as e:
        logger.error(f"Error running Trivy scan: {e}")
        return False

def _parse_trivy_results(output_file: Path) -> List[Dict[str, Any]]:
    """Parse Trivy JSON results and return standardized findings."""
    try:
        if not output_file.exists():
            logger.info("Trivy found no vulnerabilities (no output file)")
            return []
            
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
        
    except Exception as e:
        logger.error(f"Error parsing Trivy results: {e}")
        return []
