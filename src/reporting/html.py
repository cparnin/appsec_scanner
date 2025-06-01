from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def generate_html_report(results, output_dir):
    """
    Generate an HTML report from the combined scanner results.
    
    Args:
        results (dict): Scanner results keyed by tool name (semgrep, gitleaks, sca)
        output_dir (Path): Directory to write the HTML report
    """
    try:
        # Load Jinja2 template
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html")
        
        # Count total findings across all tools
        total_findings = sum(len(findings) for findings in results.values())
        
        # Render template with findings data
        html_content = template.render(
            results=results,
            total_findings=total_findings
        )
        
        # Write HTML report
        report_path = output_dir / "report.html"
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