from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_html_report(results, output_dir, repo_path=None):
    """
    Generate an HTML report from the combined scanner results.
    
    Args:
        results (dict): Scanner results keyed by tool name (semgrep, gitleaks, sca)
        output_dir (Path): Directory to write the HTML report
        repo_path (str): Path to the scanned repository
    """
    
    def sort_by_severity(finding):
        """Sort findings by severity priority: Critical > High > Medium > Low > Info"""
        severity = (finding.get('extra', {}).get('severity') or 
                   finding.get('severity', '')).lower()
        
        # Map severity to sort order (lower number = higher priority)
        severity_order = {
            'critical': 1,
            'error': 2,    # Semgrep often uses ERROR for high severity
            'high': 2, 
            'medium': 3,
            'warning': 4,  # Semgrep often uses WARNING for medium/low
            'low': 4,
            'info': 5,
            '': 6          # Unknown severity goes last
        }
        return severity_order.get(severity, 6)
    
    try:
        # Load Jinja2 template
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html")
        
        # Sort findings by severity for each tool
        sorted_results = {}
        for tool, findings in results.items():
            if findings:
                sorted_results[tool] = sorted(findings, key=sort_by_severity)
            else:
                sorted_results[tool] = findings
        
        # Count total findings across all tools
        total_findings = sum(len(findings) for findings in sorted_results.values())
        
        # Render template with findings data
        html_content = template.render(
            results=sorted_results,
            total_findings=total_findings,
            repo_path=repo_path or "Unknown Repository"
        )
        
        # Write HTML report
        report_path = output_dir / f"report.html"
        report_path.write_text(html_content)
        logger.info(f"HTML report generated: {report_path}")
        
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        # Create fallback report
        fallback_html = """
        <html>
        <head><title>Security Scan Report</title></head>
        <body>
        <h1>Security Scan Report</h1>
        <p><strong>Error:</strong> Failed to generate full report.</p>
        <p>Check the logs for details.</p>
        </body>
        </html>
        """
        (output_dir / "report.html").write_text(fallback_html)