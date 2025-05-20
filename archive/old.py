#!/usr/bin/env python3
"""
🛡️ AppSec Scanner: Comprehensive Security Analysis Pipeline

This tool provides a modular application security scanning pipeline that combines:
*  SAST (Static Application Security Testing) using Semgrep
*  SCA (Software Composition Analysis) using language-specific tools
*  Secrets scanning using TruffleHog
*  AI-driven remediation suggestions
*  HTML report generation listing only CRITICAL & HIGH issues in severity order

The scanner prioritizes findings by severity and provides actionable remediation steps.
"""

import os
import sys
import logging
import shutil
import subprocess
import webbrowser
import json
import re
import math
import argparse
import multiprocessing
from pathlib import Path
from dotenv import load_dotenv
from jinja2 import Template
from openai import OpenAI
from git import Repo
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# === CONFIGURATION ===
OUTPUT_DIR = Path("outputs")  # Output directory for JSON and HTML
JOBS = os.getenv("SEMGREP_JOBS") or str(multiprocessing.cpu_count())  # Semgrep parallel jobs
CONTEXT_LINES = 5  # Lines of code context in snippets
MAX_FINDINGS = 100  # Maximum number of findings to process with AI
# Set batch size for AI remediation
AI_BATCH_SIZE = 2

# Define severity mapping for consistent reporting
SEVERITY_MAP = {
    'CRITICAL': 'CRITICAL',
    'HIGH': 'HIGH'
}

# Semgrep rule packs: baseline OWASP + language-specific entries
SEMGREP_DEFAULT = "p/owasp-top-ten"  # Default OWASP Top 10 rules
SEMGREP_CONFIGS = [SEMGREP_DEFAULT]  # List of rule configurations to use

# Community Editions used below (*.security packs require pro)
LANGUAGE_RULE_MAP = {
    'Python':     'p/python',      # Python-specific security rules
    'JavaScript': 'p/javascript',  # JavaScript security rules
    'TypeScript': 'p/typescript',  # TypeScript security rules
    'Java':       'p/java',        # Java security rules
    'Terraform':  'p/terraform',   # Terraform security rules
    'Go':         'p/go',          # Go security rules
    'Ruby':       'p/ruby',        # Ruby security rules
    'C#':         'p/csharp',      # C# security rules
}

# Scanner definitions with their corresponding functions
# Each tuple contains (scanner_name, scanner_function, is_required)
SCANNERS = [
    ("Semgrep", lambda tgt, out: semgrep_scan(tgt, out), True),      # Primary SAST
    ("SCA", lambda tgt, _: sca_scan(tgt), True),              # Dependency scanning
    ("Secrets", lambda tgt, out: secret_scan(tgt, out), True),       # Secrets detection
]

# === HTML REPORT TEMPLATE ===
REPORT_TEMPLATE = Template("""
<html><head>
<title>Security Scan Report - {{ timestamp }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; }
  table { border-collapse: collapse; margin: 0 auto; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 12px; vertical-align: top; }
  th { background-color: #f5f5f5; text-align: left; }
  td { white-space: pre-wrap; }
  .critical { background-color: #ffebee; }
  .high { background-color: #fff3e0; }
  .summary { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
  pre {
    background-color: #f8f9fa;
    padding: 10px;
    border-radius: 3px;
    margin: 5px 0;
    overflow-x: auto;
    white-space: pre;
    max-width: none;
    display: block;
  }
  .severity-critical { color: #d32f2f; font-weight: bold; }
  .severity-high { color: #f57c00; font-weight: bold; }
  .tool-badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.9em;
    font-weight: bold;
    margin-right: 8px;
  }
  .tool-semgrep { background-color: #e3f2fd; color: #1565c0; }
  .tool-trufflehog { background-color: #fce4ec; color: #c2185b; }
  .tool-sca { background-color: #fff3e0; color: #ef6c00; }
  .remediation-section { margin-bottom: 8px; }
  .remediation-section pre { background-color: #f1f8e9; border-left: 4px solid #2e7d32; }
  
  /* Column width adjustments */
  th:nth-child(1), td:nth-child(1) { width: 80px; }  /* Tool */
  th:nth-child(2), td:nth-child(2) { width: 80px; }  /* Severity */
  th:nth-child(3), td:nth-child(3) { width: 200px; } /* Location */
  th:nth-child(4), td:nth-child(4) { width: 150px; } /* Rule ID */
  th:nth-child(5), td:nth-child(5) { width: 300px; } /* Description */
  th:nth-child(6), td:nth-child(6) { width: 250px; } /* Code Snippet */
  th:nth-child(7), td:nth-child(7) { width: 300px; } /* Remediation */
  
  /* Ensure code snippets are scrollable but not too wide */
  td.code-snippet { 
    max-width: 250px;
    overflow-x: auto;
  }
  
  /* Make description text more readable */
  td:nth-child(5) {
    min-width: 300px;
    max-width: 300px;
  }
</style>
</head><body>
<h1>Security Findings Report</h1>
<div class="summary">
  <p><strong>Scan Date:</strong> {{ timestamp }}</p>
  <p><strong>Target:</strong> {{ target_name }}</p>
  <p><strong>Languages Detected:</strong> {{ languages|join(', ') }}</p>
  <p><strong>Total Findings:</strong> {{ findings|length }}</p>
  <p><strong>Critical Issues:</strong> {{ critical_count }}</p>
  <p><strong>High Issues:</strong> {{ high_count }}</p>
</div>
<table>
  <tr>
    <th>Tool</th>
    <th>Severity</th>
    <th>Location</th>
    <th>Rule ID</th>
    <th>Description</th>
    <th>Code Snippet</th>
    <th>Remediation</th>
  </tr>
  {% for f, r in rows %}
  <tr class="{{ f.severity|lower }}">
    <td><span class="tool-badge tool-{{ f.tool|lower }}">{{ f.tool }}</span></td>
    <td class="severity-{{ f.severity|lower }}">{{ f.severity }}</td>
    <td>{{ f.file }}:{{ f.line }}</td>
    <td>{{ f.rule }}</td>
    <td>{{ f.message }}</td>
    <td class="code-snippet"><pre>{{ f.snippet }}</pre></td>
    <td class="remediation">
      {% set is_placeholder = (r.explanation.strip() in ['', '**Explanation**', '[Explanation]', 'No automated remediation available.']) and not r.codefix and not r.notes %}
      {% if is_placeholder %}
        <div class="remediation-section"><i>No automated remediation available.</i></div>
      {% else %}
        {% if r.explanation %}<div class="remediation-section"><b>Explanation:</b><br>{{ r.explanation }}</div>{% endif %}
        {% if r.codefix %}<div class="remediation-section"><b>Code Fix:</b><br>{% if '```' in r.codefix %}{{ r.codefix|replace('```', '<pre>')|replace('```', '</pre>')|safe }}{% else %}<pre>{{ r.codefix }}</pre>{% endif %}</div>{% endif %}
        {% if r.notes %}<div class="remediation-section"><b>Additional Notes:</b><br>{{ r.notes }}</div>{% endif %}
        {% if not (r.explanation or r.codefix or r.notes) %}—{% endif %}
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
</body></html>
""")

# === UTILITY FUNCTIONS ===
def setup_logging(verbose: bool):
    """
    Configure console logging with appropriate level and format.
    Args:
        verbose: If True, use DEBUG level, otherwise INFO
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def check_dependencies():
    """
    Ensure all required tools are present in PATH.
    Exits with error if any required tool is missing.
    """
    required_tools = {
        'semgrep': 'Semgrep CLI',
        'git': 'Git',
        'dependency-check': 'OWASP Dependency-Check',
        'trufflehog': 'TruffleHog'
    }
    
    missing = []
    for tool, name in required_tools.items():
        if not shutil.which(tool):
            missing.append(f"{name} ({tool})")
    
    if missing:
        logging.error("Missing required tools:")
        for tool in missing:
            logging.error(f"  - {tool}")
        sys.exit(1)

def run_cmd(cmd, capture_output: bool = True, timeout: int = 300, cwd: str = None, shell: bool = False) -> tuple[bool, str]:
    """
    Execute a shell command and return success status and output.
    Args:
        cmd: Command to execute as list of strings or a shell string
        capture_output: Whether to capture and return command output
        timeout: Maximum execution time in seconds (default: 5 minutes)
        cwd: Working directory to run the command in
        shell: Whether to run the command in the shell
    Returns:
        Tuple of (success, output)
    """
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            cwd=cwd,
            shell=shell
        )
        return True, result.stdout if capture_output else ""
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out after {timeout} seconds: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        return False, f"Command timed out after {timeout} seconds"
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
        return False, e.stderr if capture_output else ""

# === LANGUAGE DETECTION ===
ext_map = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.java': 'Java',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.tf': 'Terraform',
    '.hcl': 'Terraform',
    '.tsx': 'TypeScript',
    '.jsx': 'JavaScript',
    '.vue': 'JavaScript',
    '.php': 'PHP',
    '.cs': 'C#',
    '.yml': 'YAML',
    '.yaml': 'YAML',
}

def detect_languages(target: Path) -> list:
    """
    Detect project languages by file extension.
    Args:
        target: Path to the target repository
    Returns:
        Sorted list of detected programming languages
    """
    langs = set()
    for root, _, files in os.walk(target):
        for fname in files:
            lang = ext_map.get(Path(fname).suffix.lower())
            if lang:
                langs.add(lang)
    return sorted(langs)

# === OPENAI CLIENT INITIALIZATION ===
def init_openai() -> OpenAI:
    """
    Initialize OpenAI client with API key from environment.
    Returns:
        OpenAI client instance
    Raises:
        SystemExit if API key is not configured
    """
    load_dotenv()
    key = os.getenv('OPENAI_API_KEY')
    if not key:
        logging.error('Environment variable OPENAI_API_KEY not set.')
        sys.exit(1)
    return OpenAI(api_key=key)

# === SNIPPET EXTRACTION ===
def extract_snippet(file: Path, line: int) -> str:
    """
    Extract code snippet around the specified line.
    Args:
        file: Path to the source file
        line: Line number to extract context around
    Returns:
        Code snippet with context lines
    """
    try:
        lines = file.read_text().splitlines()
        start = max(0, line - 1 - CONTEXT_LINES)
        end = min(len(lines), line + CONTEXT_LINES)
        return '\n'.join(lines[start:end])
    except Exception as e:
        logging.debug(f"Snippet extraction error: {e}")
        return ''

# === SCANNER IMPLEMENTATIONS ===
def semgrep_scan(target: Path, out_json: Path) -> list:
    """
    Run Semgrep analysis on the target repository.
    Args:
        target: Path to the target repository
        out_json: Path to output JSON file
    Returns:
        List of security findings
    """
    if not shutil.which('semgrep'):
        logging.error("Semgrep not found. Please install it first.")
        return []

    findings = []
    for config in SEMGREP_CONFIGS:
        try:
            logging.info(f"[Semgrep] Running with config: {config}")
            success, output = run_cmd([
                'semgrep',
                '--config', config,
                '--json',
                '--jobs', JOBS,
                str(target)
            ], timeout=600)  # 10 minute timeout for Semgrep
            if not success:
                logging.error(f"[Semgrep] Scan failed with config {config}")
                continue
            data = json.loads(output)
            for result in data.get('results', []):
                # Map Semgrep severities to only CRITICAL and HIGH
                raw_sev = result.get('extra', {}).get('severity', '').upper()
                if raw_sev == 'CRITICAL':
                    severity = 'CRITICAL'
                elif raw_sev in ('ERROR', 'HIGH'):
                    severity = 'HIGH'
                else:
                    continue  # Ignore lower severities
                findings.append({
                    'tool': 'Semgrep',
                    'file': result.get('path', ''),
                    'line': result.get('start', {}).get('line', 0),
                    'severity': severity,
                    'rule': result.get('check_id', ''),
                    'message': result.get('extra', {}).get('message', ''),
                    'snippet': result.get('extra', {}).get('lines', '')
                })
        except Exception as e:
            logging.error(f"Semgrep scan failed with config {config}: {e}")
            continue
    return findings

def sca_scan(target: Path) -> list:
    """
    Run Software Composition Analysis using language-specific tools.
    Args:
        target: Path to the target repository
    Returns:
        List of security findings with attributes:
        - tool: Name of the tool used
        - file: Path to the file with the issue
        - line: Line number of the issue
        - severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
        - rule: Rule ID or CVE ID
        - message: Description of the issue
        - snippet: Code snippet showing the issue
    """
    findings = []
    
    # Check for Node.js/TypeScript
    if (target / 'package.json').exists():
        logging.info(f"[SCA] Running: npm audit in {target}")
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=target,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                try:
                    audit_data = json.loads(result.stdout)
                    for vuln in audit_data.get('advisories', {}).values():
                        severity = vuln.get('severity', 'LOW').upper()
                        if severity in ('CRITICAL', 'HIGH'):
                            findings.append({
                                'tool': 'npm-audit',
                                'file': vuln.get('findings', [{}])[0].get('paths', [''])[0],
                                'line': 0,
                                'severity': severity,
                                'rule': vuln.get('cves', [''])[0] if vuln.get('cves') else vuln.get('id'),
                                'message': vuln.get('overview', ''),
                                'snippet': ''
                            })
                except json.JSONDecodeError:
                    logging.error(f"[SCA] Failed to parse npm audit output: {result.stdout}")
        except subprocess.TimeoutExpired:
            logging.error("[SCA] npm audit timed out after 5 minutes")
    
    # Check for Java
    if (target / 'pom.xml').exists() or (target / 'build.gradle').exists():
        logging.info(f"[SCA] Running: dependency-check in {target}")
        try:
            result = subprocess.run(
                ['dependency-check', '--scan', str(target), '--format', 'JSON', '--out', str(target / 'reports')],
                capture_output=True,
                text=True,
                timeout=900
            )
            if result.returncode != 0:
                try:
                    report_path = target / 'reports' / 'dependency-check-report.json'
                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)
                            for dep in report_data.get('dependencies', []):
                                for vuln in dep.get('vulnerabilities', []):
                                    severity = vuln.get('severity', 'LOW').upper()
                                    if severity in ('CRITICAL', 'HIGH'):
                                        findings.append({
                                            'tool': 'dependency-check',
                                            'file': dep.get('filePath', ''),
                                            'line': 0,
                                            'severity': severity,
                                            'rule': vuln.get('name', ''),
                                            'message': vuln.get('description', ''),
                                            'snippet': ''
                                        })
                except json.JSONDecodeError:
                    logging.error(f"[SCA] Failed to parse dependency-check output: {result.stdout}")
        except subprocess.TimeoutExpired:
            logging.error("[SCA] dependency-check timed out after 15 minutes")
    
    return findings

def secret_scan(target: Path, out_json: Path) -> list:
    """
    Run TruffleHog for secrets scanning.
    Args:
        target: Path to the target repository
        out_json: Path to output JSON file
    Returns:
        List of security findings
    """
    if not shutil.which('trufflehog'):
        logging.error("TruffleHog not found. Please install it first.")
        return []
    
    try:
        # Run trufflehog with filesystem mode and exclusions
        success, output = run_cmd([
            'trufflehog',
            '--json',
            '--exclude-dir', '.git',
            '--exclude-dir', 'node_modules',
            '--exclude-dir', 'vendor',
            '--exclude-dir', 'dist',
            '--exclude-dir', 'build',
            '--exclude-dir', 'target',
            '--exclude-dir', '__pycache__',
            '--exclude-dir', '.venv',
            '--exclude-dir', 'venv',
            '--exclude-dir', 'env',
            '--exclude-dir', '.env',
            '--exclude-dir', 'outputs',
            '--exclude-dir', 'ix',
            '--only-verified',  # Reduce false positives
            str(target)
        ], timeout=300)  # 5 minute timeout for TruffleHog
        
        if not success:
            logging.error("[Secrets] TruffleHog scan failed")
            return []
        
        findings = []
        for line in output.splitlines():
            try:
                data = json.loads(line)
                severity = 'CRITICAL'  # All secrets are critical
                findings.append({
                    'tool': 'TruffleHog',
                    'file': data.get('path', ''),
                    'line': data.get('line', 0),
                    'severity': severity,
                    'rule': 'SECRET-LEAK',
                    'message': f"Potential secret found: {data.get('reason', '')}",
                    'snippet': data.get('raw', '')
                })
            except json.JSONDecodeError:
                continue
        
        return findings
    except Exception as e:
        logging.error(f"TruffleHog scan failed: {e}")
        import traceback
        traceback.print_exc()
        return []

# === AI-DRIVEN REMEDIATION ===
def ai_suggestions(client: OpenAI, findings: list) -> list:
    """
    Generate AI-powered remediation suggestions for findings.
    Args:
        client: OpenAI client instance
        findings: List of security findings
    Returns:
        List of remediation suggestions
    """
    if not findings:
        return []
    findings = findings[:MAX_FINDINGS]
    suggestions = [None] * len(findings)
    total = len(findings)
    # Use the new batch size
    batches = math.ceil(total / AI_BATCH_SIZE)
    for i in range(batches):
        s = i * AI_BATCH_SIZE
        e = min((i + 1) * AI_BATCH_SIZE, total)
        batch = findings[s:e]
        def get_lang_from_file(file):
            ext = Path(file).suffix.lower()
            return {
                '.cs': 'C#',
                '.py': 'Python',
                '.js': 'JavaScript',
                '.ts': 'TypeScript',
                '.java': 'Java',
                '.go': 'Go',
                '.rb': 'Ruby',
                '.php': 'PHP',
            }.get(ext, 'Unknown')
        lang_prompts = {
            'C#': (
                'You are an expert AppSec engineer specializing in C# and .NET secure coding. For this C# finding, which is vulnerable to a security issue, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic C# code fix (e.g., for SQL injection, use parameterized queries with SqlCommand and SqlParameter).\n'
                '3. Any additional security considerations for C# and .NET.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'Python': (
                'You are an expert AppSec engineer specializing in Python secure coding. For this Python finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic Python code fix (e.g., use parameterized queries with DB-API, avoid eval/exec, etc).\n'
                '3. Any additional security considerations for Python.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'JavaScript': (
                'You are an expert AppSec engineer specializing in JavaScript/Node.js secure coding. For this JavaScript finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic JavaScript code fix (e.g., use parameterized queries, avoid dangerous APIs, etc).\n'
                '3. Any additional security considerations for JavaScript/Node.js.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'TypeScript': (
                'You are an expert AppSec engineer specializing in TypeScript/Node.js secure coding. For this TypeScript finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic TypeScript code fix.\n'
                '3. Any additional security considerations for TypeScript/Node.js.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'Java': (
                'You are an expert AppSec engineer specializing in Java secure coding. For this Java finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic Java code fix (e.g., use PreparedStatement for SQL, avoid reflection, etc).\n'
                '3. Any additional security considerations for Java.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'Go': (
                'You are an expert AppSec engineer specializing in Go secure coding. For this Go finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic Go code fix.\n'
                '3. Any additional security considerations for Go.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'Ruby': (
                'You are an expert AppSec engineer specializing in Ruby secure coding. For this Ruby finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic Ruby code fix.\n'
                '3. Any additional security considerations for Ruby.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'PHP': (
                'You are an expert AppSec engineer specializing in PHP secure coding. For this PHP finding, provide:\n'
                '1. A brief explanation of the vulnerability and why the code is unsafe.\n'
                '2. A secure, idiomatic PHP code fix.\n'
                '3. Any additional security considerations for PHP.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
            'Unknown': (
                'You are an expert AppSec engineer. For this finding, provide:\n'
                '1. A brief explanation of the vulnerability.\n'
                '2. A secure, idiomatic code fix.\n'
                '3. Any additional security considerations.\n'
                '\nFormat your response as:\n1. [Explanation]\n2. [Code Fix] (in a markdown code block)\n3. [Additional Notes]'
            ),
        }
        for idx, f in enumerate(batch):
            lang = get_lang_from_file(f['file'])
            prompt = lang_prompts.get(lang, lang_prompts['Unknown'])
            prompt_lines = [prompt, '', 'Finding:']
            prompt_lines.extend([
                f"[Severity] {f['severity']}",
                f"Tool: {f['tool']}",
                f"Rule: {f['rule']}",
                f"File: {f['file']}:{f['line']}",
                f"Message: {f['message']}",
                f"Code:\n{f['snippet']}"
            ])
            try:
                resp = client.chat.completions.create(
                    model='gpt-4o-mini',
                    messages=[
                        {'role': 'system', 'content': 'You are an expert AppSec engineer specializing in secure coding practices and vulnerability remediation.'},
                        {'role': 'user', 'content': '\n'.join(prompt_lines)}
                    ],
                    temperature=0.2,
                    max_tokens=500
                )
                suggestions[s + idx] = resp.choices[0].message.content.strip()
            except Exception as e:
                logging.error(f"AI suggestion generation failed for finding {s + idx+1} ({lang}): {e}")
                continue
    return [s or '' for s in suggestions]

# === HTML REPORT GENERATION ===
def parse_ai_suggestion(s):
    if not s:
        return {'explanation': 'No automated remediation available.', 'codefix': '', 'notes': ''}
    explanation, codefix, notes = '', '', ''
    current = None
    # Try to split by 1., 2., 3. or fallback to lines
    parts = re.split(r'\n?\s*\d\.\s*', s)
    if len(parts) >= 2:
        explanation = parts[1].strip()
    if len(parts) >= 3:
        codefix = parts[2].strip()
    if len(parts) >= 4:
        notes = parts[3].strip()
    # Fallback: if nothing parsed, just put the whole thing in explanation
    if not (explanation or codefix or notes):
        explanation = 'No automated remediation available.'
    return {
        'explanation': explanation or 'No automated remediation available.',
        'codefix': codefix,
        'notes': notes
    }

def html_report(findings: list, suggestions: list, out: Path, languages: list, target_name: str):
    """
    Generate and open HTML report.
    Args:
        findings: List of security findings
        suggestions: List of remediation suggestions
        out: Output file path
        languages: List of detected languages
        target_name: Name of the target repository
    """
    # Parse AI suggestions into dicts
    parsed_suggestions = []
    for s in suggestions:
        parsed = parse_ai_suggestion(s)
        parsed_suggestions.append(parsed)
    
    # Filter findings to only include CRITICAL and HIGH severities
    filtered_findings = [f for f in findings if f['severity'] in ('CRITICAL', 'HIGH')]
    rows = list(zip(filtered_findings, parsed_suggestions))
    # Only count CRITICAL and HIGH
    critical_count = sum(1 for f in filtered_findings if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in filtered_findings if f['severity'] == 'HIGH')
    html = REPORT_TEMPLATE.render(
        rows=rows,
        findings=filtered_findings,
        languages=languages,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_name=target_name,
        critical_count=critical_count,
        high_count=high_count
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    logging.info(f"Report written to {out}")
    webbrowser.open(out.resolve().as_uri())

# === TARGET RESOLUTION ===
def resolve_target(arg: str) -> Path:
    """
    Convert --target argument (index, URL, or path) into a Path to scan.
    Args:
        arg: Target argument (index, URL, or path)
    Returns:
        Path to the target repository
    Raises:
        SystemExit if target is invalid
    """
    # Look for ix/ directory one level up
    ix_dir = Path.cwd().parent / 'ix'
    if not ix_dir.exists():
        logging.error("ix/ directory not found in parent directory. Please create it first.")
        sys.exit(1)
        
    dirs = [d for d in ix_dir.iterdir() if d.is_dir()]
    if arg.isdigit():
        idx = int(arg)
        if 0 <= idx < len(dirs):
            return dirs[idx]
    if arg.startswith(('http://', 'https://')):
        name = ix_dir / Path(urlparse(arg).path).stem
        Repo.clone_from(arg, name)
        return name
    p = Path(arg)
    if p.exists() and p.is_dir():
        return p
    logging.error(f"Invalid target: {arg}")
    sys.exit(1)

def main():
    """Main entry point for the security scanner."""
    # Look for ix/ directory one level up
    ix_dir = Path.cwd().parent / 'ix'
    if not ix_dir.exists():
        logging.error("ix/ directory not found in parent directory. Please create it first.")
        sys.exit(1)

    # Get list of repositories in ix/
    repos = [d for d in ix_dir.iterdir() if d.is_dir()]
    if not repos:
        logging.error("No repositories found in ix/ directory.")
        sys.exit(1)

    # Ask for scan type
    print("\nSelect scan type:")
    print("1. Semgrep (SAST)")
    print("2. SCA (Software Composition Analysis)")
    print("3. TruffleHog (Secrets scanning)")
    print("4. All scans")
    
    while True:
        try:
            scan_choice = int(input("\nEnter scan type (1-4): "))
            if 1 <= scan_choice <= 4:
                break
            print("Please enter a number between 1 and 4")
        except ValueError:
            print("Please enter a valid number")

    # Map scan choice to scan type
    scan_map = {
        1: "semgrep",
        2: "sca",
        3: "trufflehog",
        4: "all"
    }
    scan_type = scan_map[scan_choice]

    # Ask for repository selection
    print("\nAvailable repositories:")
    for i, repo in enumerate(repos):
        print(f"{i+1}. {repo.name}")
    
    while True:
        try:
            repo_choice = int(input("\nSelect repository (enter number): "))
            if 1 <= repo_choice <= len(repos):
                break
            print(f"Please enter a number between 1 and {len(repos)}")
        except ValueError:
            print("Please enter a valid number")

    target = repos[repo_choice - 1]
    print(f"\nSelected repository: {target.name}")
    print(f"Selected scan type: {scan_type}")

    setup_logging(False)  # Set to False for cleaner output
    check_dependencies()

    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Detect languages in the target
    languages = detect_languages(target)
    print(f"Detected languages: {', '.join(languages)}")

    # Initialize OpenAI client for AI suggestions
    client = init_openai()

    # Select scanners based on scan type
    selected_scanners = []
    if scan_type == "all":
        selected_scanners = SCANNERS
    else:
        scanner_map = {
            "semgrep": ("Semgrep", lambda tgt, out: semgrep_scan(tgt, out), True),
            "sca": ("SCA", lambda tgt, _: sca_scan(tgt), True),
            "trufflehog": ("Secrets", lambda tgt, out: secret_scan(tgt, out), True)
        }
        selected_scanners = [scanner_map[scan_type]]

    all_findings = []
    for scanner_name, scanner_func, _ in selected_scanners:
        print(f"\nRunning {scanner_name} scan...")
        out_json = OUTPUT_DIR / f"{scanner_name.lower()}_{timestamp}.json"
        findings = scanner_func(target, out_json)
        all_findings.extend(findings)
        
        # Generate individual report for this scanner
        if findings:
            suggestions = ai_suggestions(client, findings)
            report_path = OUTPUT_DIR / f"{scanner_name.lower()}_report_{timestamp}.html"
            html_report(findings, suggestions, report_path, languages, target.name)
            print(f"Generated {scanner_name} report: {report_path}")
            webbrowser.open(f"file://{report_path.absolute()}")

    if not all_findings:
        print("\nNo security findings detected.")
        return

    # Generate combined report if multiple scanners were run
    if len(selected_scanners) > 1:
        suggestions = ai_suggestions(client, all_findings)
        report_path = OUTPUT_DIR / f"combined_report_{timestamp}.html"
        html_report(all_findings, suggestions, report_path, languages, target.name)
        print(f"Generated combined report: {report_path}")
        webbrowser.open(f"file://{report_path.absolute()}")

if __name__ == "__main__":
    main()
