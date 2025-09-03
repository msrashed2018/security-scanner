"""
Scanner HTML report generator.
Converts individual scanner JSON results to formatted HTML reports.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import logging

from src.core.template_loader import TemplateLoader

logger = logging.getLogger(__name__)


class ScannerReportGenerator:
    """Generates HTML reports from scanner JSON files."""
    
    def __init__(self):
        self.template_loader = TemplateLoader()
    
    def generate_scanner_report(self, scanner_file: Path, target_name: str) -> str:
        """Generate HTML report for a single scanner result."""
        try:
            with open(scanner_file, 'r') as f:
                scanner_data = json.load(f)
            
            scanner_name = scanner_file.stem
            scan_id = scanner_file.parts[-4]
            html_content = self._generate_scanner_html(scanner_data, scanner_name, target_name, scan_id)
            
            # Create HTML file in the same directory
            html_file = scanner_file.parent / f"scanner-report-{scanner_name}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Generated scanner HTML report: {html_file}")
            return str(html_file)
            
        except Exception as e:
            logger.error(f"Failed to generate scanner report for {scanner_file}: {e}")
            return ""
    
    def generate_all_scanner_reports(self, scan_dir: Path) -> None:
        """Generate HTML reports for all scanner files in a scan directory."""
        targets_dir = scan_dir / "targets"
        if not targets_dir.exists():
            return
        
        for target_dir in targets_dir.iterdir():
            if target_dir.is_dir():
                scanners_dir = target_dir / "scanners"
                if scanners_dir.exists():
                    for scanner_file in scanners_dir.iterdir():
                        if scanner_file.is_file() and scanner_file.suffix == '.json':
                            self.generate_scanner_report(scanner_file, target_dir.name)
    
    def _generate_scanner_html(self, scanner_data: Dict[str, Any], scanner_name: str, target_name: str, scan_id: str) -> str:
        """Generate HTML content for scanner data."""
        
        findings = self._extract_findings(scanner_data)
        stats = self._calculate_stats(findings)
        
        findings_html = self._generate_findings_html(findings)
        metadata_html = self._generate_metadata_html(scanner_data)
        summary_stats_html = self.template_loader.render('summary_stats.html', stats)

        css_styles = self.template_loader.load_template('scanner_report.css')
        javascript = self.template_loader.load_template('javascript_scanner.js')

        report_data = {
            'scan_id': scan_id,
            'scanner_name': scanner_name.title(),
            'target_name': target_name,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_findings': len(findings),
            'summary_stats': summary_stats_html,
            'findings_cards': findings_html,
            'metadata_section': metadata_html,
            'css_styles': css_styles,
            'javascript': javascript,
            'year': datetime.now().year
        }
        
        return self.template_loader.render('scanner_report.html', report_data)
    
    def _extract_findings(self, scanner_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from various scanner data structures."""
        findings = []
        
        if isinstance(scanner_data, dict):
            if 'findings' in scanner_data:
                findings = scanner_data['findings']
            elif 'results' in scanner_data:
                findings = scanner_data['results']
            elif 'vulnerabilities' in scanner_data:
                findings = scanner_data['vulnerabilities']
            elif 'details' in scanner_data:  # Dockle format
                findings = scanner_data['details']
            elif 'matches' in scanner_data:  # Grype format
                findings = scanner_data['matches']
            elif 'artifacts' in scanner_data:  # Syft format
                findings = scanner_data['artifacts']
            elif 'Results' in scanner_data:  # Trivy format
                trivy_results = scanner_data['Results']
                if isinstance(trivy_results, list):
                    for result in trivy_results:
                        if 'Vulnerabilities' in result:
                            findings.extend(result['Vulnerabilities'])
                        if 'Misconfigurations' in result:
                            findings.extend(result['Misconfigurations'])
        elif isinstance(scanner_data, list):
            findings = scanner_data
        
        return findings if isinstance(findings, list) else []
    
    def _calculate_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate statistics from findings."""
        stats = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = self._get_severity(finding).lower()
            if severity in stats:
                stats[severity] += 1
            else:
                stats['info'] += 1
        
        return stats
    
    def _get_severity(self, finding: Dict[str, Any]) -> str:
        """Extract severity from finding data."""
        severity_fields = ['severity', 'Severity', 'level', 'Level', 'priority', 'Priority']
        
        for field in severity_fields:
            if field in finding:
                severity = finding[field]
                if isinstance(severity, str):
                    return severity.upper()
                elif isinstance(severity, dict) and 'level' in severity:
                    return severity['level'].upper()
        
        return 'INFO'
    
    def _generate_findings_html(self, findings: List[Dict[str, Any]]) -> str:
        """Generate HTML for findings list."""
        if not findings:
            return '<div class="no-findings">No findings detected by this scanner.</div>'
        
        html = ""
        for finding in findings:
            severity = self._get_severity(finding)
            finding_data = {
                'finding_type': self._get_finding_title(finding),
                'severity': severity,
                'severity_class': severity.lower(),
                'description': self._get_finding_description(finding),
                'location': self._get_finding_location(finding),
                'raw_data': json.dumps(finding, indent=2)
            }
            html += self.template_loader.render('finding_card.html', finding_data)
        
        return html
    
    def _get_finding_title(self, finding: Dict[str, Any]) -> str:
        """Extract title from finding data."""
        title_fields = ['title', 'Title', 'name', 'Name', 'id', 'ID', 'code', 'VulnerabilityID', 'PkgName']
        
        for field in title_fields:
            if field in finding and finding[field]:
                return str(finding[field])
        
        return "Security Finding"
    
    def _get_finding_description(self, finding: Dict[str, Any]) -> str:
        """Extract description from finding data."""
        desc_fields = ['description', 'Description', 'message', 'Message', 'summary', 'Summary']
        
        for field in desc_fields:
            if field in finding and finding[field]:
                return str(finding[field])
        
        return "No description available"
    
    def _get_finding_location(self, finding: Dict[str, Any]) -> str:
        """Extract location from finding data."""
        location_fields = ['location', 'Location', 'path', 'Path', 'file', 'File', 'PkgPath']
        
        for field in location_fields:
            if field in finding and finding[field]:
                return str(finding[field])
        
        return ""
    
    def _generate_metadata_html(self, scanner_data: Dict[str, Any]) -> str:
        """Generate metadata section."""
        # Extract target information from different possible locations
        target_info = 'N/A'
        if 'target' in scanner_data:
            target_info = scanner_data['target']
        elif 'source' in scanner_data:
            target_info = scanner_data['source']
        elif 'artifact' in scanner_data and isinstance(scanner_data['artifact'], dict):
            target_info = scanner_data['artifact'].get('name', 'N/A')
        elif 'Results' in scanner_data and isinstance(scanner_data['Results'], list) and len(scanner_data['Results']) > 0:
            # For Trivy format
            target_info = scanner_data['Results'][0].get('Target', 'N/A')
        
        metadata = {
            'scanner_name': scanner_data.get('scanner', {}).get('name', 'N/A'),
            'scanner_version': scanner_data.get('scanner', {}).get('version', 'N/A'),
            'scan_start_time': scanner_data.get('start_time', 'N/A'),
            'scan_end_time': scanner_data.get('end_time', 'N/A'),
            'target': target_info
        }
        return self.template_loader.render('metadata_section.html', metadata)