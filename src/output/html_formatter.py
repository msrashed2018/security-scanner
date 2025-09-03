"""
HTML output formatter for security scan reports.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List
import json
import subprocess
import sys

from .formatters import BaseFormatter
from ..core.models import ScanSummary, ScanResult, Finding, SeverityLevel
from ..core.config import OutputConfig
from ..core.template_loader import template_loader


class HtmlFormatter(BaseFormatter):
    """HTML output formatter."""
    
    @property
    def format_name(self) -> str:
        return "html"
    
    @property
    def file_extension(self) -> str:
        return "html"
    
    def generate_report(self, summary: ScanSummary, output_config: OutputConfig) -> str:
        """Generate HTML report with hierarchical structure."""
        
        # Create hierarchical output directory structure
        scan_dir = self._create_hierarchical_structure(output_config, summary)
        
        
        # Generate target-specific reports
        self._generate_target_reports(summary, scan_dir)
        
        # Generate scan metadata
        self._generate_scan_metadata(summary, scan_dir)
        
        # Generate scanner HTML reports
        self._generate_scanner_reports(scan_dir)
        
        # Generate findings browsers
        self._generate_findings_browsers(scan_dir)
        
        # Generate index files using the index generator
        self._generate_index_files(output_config.base_dir)
        
        # Return findings browser as the main entry point
        return str(scan_dir / "findings-browser.html")
    
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML reports."""
        return template_loader.load_template('html_formatter.css')
    
    def _generate_severity_chart(self, counts: Dict[str, int]) -> str:
        """Generate severity chart HTML."""
        chart_html = ""
        for severity, count in counts.items():
            if count > 0:
                chart_html += f'<div class="severity-bar severity-{severity.lower()}">{severity}: {count}</div>'
        return chart_html or '<p>No findings</p>'
    
    def _generate_targets_overview(self, summary: ScanSummary) -> str:
        """Generate targets overview HTML."""
        html = ""
        target_summary = summary.target_summary
        
        for target_path, target_info in target_summary.items():
            html += f"""
            <div class="target-card">
                <h4>{target_info['target_type'].title()}: {Path(target_path).name}</h4>
                <p><strong>Path:</strong> {target_path}</p>
                <p><strong>Scanners:</strong> {', '.join(target_info['scanners_run'])}</p>
                <p><strong>Findings:</strong> {target_info['total_findings']}</p>
            </div>
            """
        
        return html
    
    def _generate_scanners_overview(self, summary: ScanSummary) -> str:
        """Generate scanners overview HTML."""
        html = ""
        scanner_summary = summary.scanner_summary
        
        for scanner_name, scanner_info in scanner_summary.items():
            html += f"""
            <div class="scanner-card">
                <h4>{scanner_name.title()}</h4>
                <p><strong>Scans:</strong> {scanner_info['successful_scans']}/{scanner_info['total_scans']} successful</p>
                <p><strong>Findings:</strong> {scanner_info['total_findings']}</p>
                <p><a href="../findings-browser.html">View Details</a></p>
            </div>
            """
        
        return html
    
    def _generate_high_priority_section(self, high_findings: List[Finding]) -> str:
        """Generate high priority findings section."""
        if not high_findings:
            return ""
        
        html = f"""
        <div class="section">
            <h2>🚨 High Priority Findings</h2>
            <p>The following {len(high_findings)} findings require immediate attention:</p>
            {self._generate_findings_list(high_findings[:10])}  <!-- Limit to top 10 -->
        </div>
        """
        
        return html
    
    def _generate_findings_list(self, findings: List[Finding]) -> str:
        """Generate findings list HTML."""
        if not findings:
            return "<p>No findings</p>"
        
        html = ""
        for finding in findings:
            severity_class = f"severity-{finding.severity.value.lower()}"
            html += f"""
            <div class="finding-item">
                <div class="finding-title">{finding.title}</div>
                <div class="finding-meta">
                    <span class="{severity_class}">{finding.severity.value}</span> | 
                    Scanner: {finding.scanner} | 
                    Location: {finding.location or 'N/A'}
                </div>
                <div class="finding-description">{finding.description}</div>
                {f'<div class="finding-remediation"><strong>Remediation:</strong> {finding.remediation}</div>' if finding.remediation else ''}
            </div>
            """
        
        return html
    
    def _generate_findings_table(self, summary: ScanSummary) -> str:
        """Generate findings table HTML."""
        if not any(result.findings for result in summary.results):
            return "<p>No findings</p>"
        
        html = """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Scanner</th>
                    <th>Target</th>
                    <th>Location</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for result in summary.results:
            for finding in result.findings:
                severity_class = f"severity-{finding.severity.value.lower()}"
                html += f"""
                <tr>
                    <td class="{severity_class}">{finding.severity.value}</td>
                    <td>{finding.title}</td>
                    <td>{finding.scanner}</td>
                    <td>{Path(finding.target).name}</td>
                    <td>{finding.location or 'N/A'}</td>
                </tr>
                """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def _generate_detailed_scanner_results(self, summary: ScanSummary) -> str:
        """Generate detailed scanner results HTML."""
        html = ""
        scanner_summary = summary.scanner_summary
        
        for scanner_name, scanner_info in scanner_summary.items():
            html += f"""
            <div class="scanner-section">
                <h3>{scanner_name.title()}</h3>
                <p><strong>Total Scans:</strong> {scanner_info['total_scans']}</p>
                <p><strong>Successful:</strong> {scanner_info['successful_scans']}</p>
                <p><strong>Failed:</strong> {scanner_info['failed_scans']}</p>
                <p><strong>Total Findings:</strong> {scanner_info['total_findings']}</p>
                <p><a href="../findings-browser.html">Browse All Findings</a></p>
            </div>
            """
        
        return html
    
    def _generate_recommendations(self, summary: ScanSummary) -> str:
        """Generate recommendations HTML."""
        recommendations = [
            "Review and address all critical and high severity findings immediately",
            "Implement automated security scanning in your CI/CD pipeline",
            "Regularly update dependencies and base images",
            "Use secrets management solutions instead of hardcoded credentials",
            "Follow security best practices for your infrastructure as code",
            "Consider implementing security policies with tools like OPA/Gatekeeper",
            "Schedule regular security scans and reviews"
        ]
        
        html = "<ul>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        return html
    
    def _create_hierarchical_structure(self, output_config: OutputConfig, summary: ScanSummary) -> Path:
        """Create hierarchical directory structure for reports."""
        from datetime import datetime
        import json
        
        # Create main scan directory
        scan_dir = Path(output_config.base_dir) / summary.scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Create organized subdirectories
        (scan_dir / "summary").mkdir(exist_ok=True)          # Executive and detailed reports
        (scan_dir / "targets").mkdir(exist_ok=True)          # Target-specific reports
        (scan_dir / "raw-data").mkdir(exist_ok=True)         # JSON outputs and SARIF files
        (scan_dir / "metadata").mkdir(exist_ok=True)         # Scan metadata
        
        return scan_dir
    
    def _generate_target_reports(self, summary: ScanSummary, scan_dir: Path) -> None:
        """Generate target-specific reports and combined findings."""
        targets_dir = scan_dir / "targets"
        
        # Group results by target
        target_results = {}
        for result in summary.results:
            target_name = self._get_safe_target_name(result.target.path)
            if target_name not in target_results:
                target_results[target_name] = []
            target_results[target_name].append(result)
        
        # Generate reports for each target
        for target_name, results in target_results.items():
            target_dir = targets_dir / target_name
            target_dir.mkdir(exist_ok=True)
            
            # Generate combined findings JSON
            combined_findings = []
            for result in results:
                for finding in result.findings:
                    combined_findings.append({
                        'scanner': result.scanner_name,
                        'severity': finding.severity.value,
                        'title': finding.title,
                        'description': finding.description,
                        'location': finding.location,
                        'remediation': finding.remediation
                    })
            
            # Write combined findings
            findings_file = target_dir / "combined_findings.json"
            with open(findings_file, 'w', encoding='utf-8') as f:
                json.dump(combined_findings, f, indent=2)
            
            # Generate scanner-specific reports
            scanners_dir = target_dir / "scanners"
            scanners_dir.mkdir(exist_ok=True)
            
            for result in results:
                scanner_file = scanners_dir / f"{result.scanner_name}.json"
                with open(scanner_file, 'w', encoding='utf-8') as f:
                    json.dump(result.to_dict(), f, indent=2)
    
    def _generate_scan_metadata(self, summary: ScanSummary, scan_dir: Path) -> None:
        """Generate scan metadata file."""
        from datetime import datetime
        import json
        
        # Calculate scanners used
        scanners_used = list(set(result.scanner_name for result in summary.results))
        scanners_used.sort()
        
        # Calculate targets count
        targets_count = len(set(result.target.path for result in summary.results))
        
        metadata = {
            'scan_id': summary.scan_id,
            'timestamp': summary.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_type': self._infer_scan_type(summary),
            'description': self._generate_scan_description(summary),
            'targets_count': targets_count,
            'total_findings': summary.total_findings,
            'scanners_used': scanners_used,
            'created_by': 'security-scanner',
            'created_at': summary.start_time.isoformat(),
            'duration': summary.duration
        }
        
        metadata_file = scan_dir / "metadata" / "scan_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
    
    def _generate_index_files(self, base_dir: str) -> None:
        """Generate index.html files using the index generator."""
        try:
            # Import and run the index generator directly instead of subprocess
            from ..utils.index_generator import ReportIndexGenerator
            
            generator = ReportIndexGenerator(base_dir)
            generator.generate_all_indexes()
            
            self.logger.info(f"Generated index files for reports in: {base_dir}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate index files: {e}")
            # Try to at least generate a basic index
            try:
                self._generate_basic_index(base_dir)
            except Exception as basic_error:
                self.logger.error(f"Failed to generate basic index: {basic_error}")
    
    def _generate_basic_index(self, base_dir: str) -> None:
        """Generate a basic index.html as fallback."""
        from pathlib import Path
        base_path = Path(base_dir)
        
        # Find scan directories
        scan_dirs = [d for d in base_path.iterdir() if d.is_dir() and d.name != '__pycache__']
        
        scan_list_html = ''.join(f'<li class="scan-item"><a href="{scan_dir.name}/index.html" class="scan-link">📊 {scan_dir.name}</a></li>' for scan_dir in scan_dirs)
        
        context = {
            'scan_list': scan_list_html
        }
        
        basic_html = template_loader.render('basic_index.html', context)
        
        index_file = base_path / "index.html"
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(basic_html)
        
        self.logger.info(f"Generated basic index file: {index_file}")
    
    def _get_safe_target_name(self, target_path: str) -> str:
        """Convert target path to safe directory name."""
        if target_path.startswith('docker://') or target_path.startswith('registry://'):
            # Handle Docker images
            name = target_path.replace('docker://', '').replace('registry://', '')
            name = name.replace(':', '_').replace('/', '_')
        else:
            # Handle file paths and other targets
            name = Path(target_path).name or target_path.replace('/', '_').replace('\\', '_')
        
        # Make safe for filesystem
        safe_name = ''.join(c for c in name if c.isalnum() or c in ('_', '-', '.'))
        return safe_name or 'unknown_target'
    
    def _infer_scan_type(self, summary: ScanSummary) -> str:
        """Infer scan type from targets."""
        target_types = set(result.target.target_type.value for result in summary.results)
        
        if 'docker' in target_types:
            return 'container'
        elif 'git' in target_types:
            return 'source_code'
        elif 'kubernetes' in target_types:
            return 'kubernetes'
        elif 'terraform' in target_types:
            return 'infrastructure'
        else:
            return 'mixed'
    
    def _generate_scan_description(self, summary: ScanSummary) -> str:
        """Generate a description for the scan."""
        target_types = set(result.target.target_type.value for result in summary.results)
        targets_count = len(set(result.target.path for result in summary.results))
        scanners_count = len(set(result.scanner_name for result in summary.results))
        
        if 'docker' in target_types:
            return f"Container security scan for {targets_count} image{'s' if targets_count != 1 else ''}"
        elif 'git' in target_types:
            return f"Source code security scan for {targets_count} repositor{'ies' if targets_count != 1 else 'y'}"
        elif 'kubernetes' in target_types:
            return f"Kubernetes security scan for {targets_count} manifest{'s' if targets_count != 1 else ''}"
        elif 'terraform' in target_types:
            return f"Infrastructure security scan for {targets_count} Terraform file{'s' if targets_count != 1 else ''}"
        else:
            return f"Security scan for {targets_count} target{'s' if targets_count != 1 else ''} using {scanners_count} scanner{'s' if scanners_count != 1 else ''}"
    
    def _generate_scanner_reports(self, scan_dir: Path) -> None:
        """Generate HTML reports for all scanner JSON files."""
        try:
            from .scanner_report_generator import ScannerReportGenerator
            generator = ScannerReportGenerator()
            generator.generate_all_scanner_reports(scan_dir)
            self.logger.info("Generated scanner HTML reports")
        except Exception as e:
            self.logger.error(f"Failed to generate scanner reports: {e}")
    
    def _generate_findings_browsers(self, scan_dir: Path) -> None:
        """Generate interactive findings browsers."""
        try:
            from .findings_browser import FindingsBrowserGenerator
            generator = FindingsBrowserGenerator()
            
            # Generate main findings browser
            generator.generate_findings_browser(scan_dir)
            
            # Generate target-specific findings viewers
            targets_dir = scan_dir / "targets"
            if targets_dir.exists():
                for target_dir in targets_dir.iterdir():
                    if target_dir.is_dir():
                        generator.generate_target_findings_viewer(target_dir)
            
            self.logger.info("Generated findings browsers")
        except Exception as e:
            self.logger.error(f"Failed to generate findings browsers: {e}")