"""
Interactive findings browser generator.
Creates HTML interfaces for browsing and filtering security findings.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import logging

from ..core.template_loader import template_loader

logger = logging.getLogger(__name__)


class FindingsBrowserGenerator:
    """Generates interactive HTML browsers for security findings."""
    
    def generate_findings_browser(self, scan_dir: Path) -> str:
        """Generate main findings browser for a scan."""
        try:
            # Collect all findings from all targets
            all_findings = self._collect_all_findings(scan_dir)
            
            # Generate HTML content
            html_content = self._generate_browser_html(all_findings, scan_dir.name)
            
            # Write browser HTML file
            browser_file = scan_dir / "findings-browser.html"
            with open(browser_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Generated findings browser: {browser_file}")
            return str(browser_file)
            
        except Exception as e:
            logger.error(f"Failed to generate findings browser for {scan_dir}: {e}")
            return ""
    
    def generate_target_findings_viewer(self, target_dir: Path) -> str:
        """Generate findings viewer for a specific target."""
        try:
            combined_file = target_dir / "combined_findings.json"
            if not combined_file.exists():
                return ""
            
            with open(combined_file, 'r') as f:
                findings = json.load(f)
            
            # Generate HTML content
            html_content = self._generate_target_findings_html(findings, target_dir.name)
            
            # Write findings viewer HTML file
            viewer_file = target_dir / "findings.html"
            with open(viewer_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Generated target findings viewer: {viewer_file}")
            return str(viewer_file)
            
        except Exception as e:
            logger.error(f"Failed to generate target findings viewer for {target_dir}: {e}")
            return ""
    
    def _collect_all_findings(self, scan_dir: Path) -> List[Dict[str, Any]]:
        """Collect all findings from all targets in a scan."""
        all_findings = []
        targets_dir = scan_dir / "targets"
        raw_data_dir = scan_dir / "raw-data"
        
        if not targets_dir.exists():
            return all_findings
        
        # Load raw scanner data to preserve original metadata
        raw_scanner_data = {}
        if raw_data_dir.exists():
            for raw_file in raw_data_dir.glob("*.json"):
                if raw_file.name.endswith("_findings.json") or raw_file.name.endswith("_summary.json"):
                    continue  # Skip processed files
                
                try:
                    with open(raw_file, 'r') as f:
                        scanner_data = json.load(f)
                        raw_scanner_data[raw_file.name] = scanner_data
                except Exception as e:
                    logger.warning(f"Failed to load raw data from {raw_file}: {e}")
        
        for target_dir in targets_dir.iterdir():
            if target_dir.is_dir():
                combined_file = target_dir / "combined_findings.json"
                if combined_file.exists():
                    try:
                        with open(combined_file, 'r') as f:
                            findings = json.load(f)
                            # Add target information and raw data to each finding
                            for finding in findings:
                                finding['target_name'] = target_dir.name
                                
                                # Try to find and attach raw scanner data
                                raw_finding = self._find_raw_finding(finding, raw_scanner_data, target_dir.name)
                                if raw_finding:
                                    finding['raw_data'] = raw_finding
                                
                                all_findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to load findings from {combined_file}: {e}")
        
        return all_findings
    
    def _find_raw_finding(self, finding: Dict[str, Any], raw_scanner_data: Dict[str, Any], target_name: str) -> Dict[str, Any]:
        """Find the original raw finding data from scanner results."""
        scanner = finding.get('scanner', '').lower()
        target = finding.get('target', '')
        title = finding.get('title', '')
        
        # Look for matching scanner file
        for filename, scanner_data in raw_scanner_data.items():
            if scanner.replace('_', '-') not in filename.lower():
                continue
                
            # Different scanners have different data structures
            if scanner == 'dockle':
                details = scanner_data.get('details', [])
                for detail in details:
                    if detail.get('title') == title:
                        return detail
            
            elif scanner == 'trivy':
                results = scanner_data.get('Results', [])
                for result in results:
                    vulnerabilities = result.get('Vulnerabilities', []) + result.get('Misconfigurations', [])
                    for vuln in vulnerabilities:
                        if vuln.get('Title') == title or vuln.get('ID') == finding.get('id'):
                            return vuln
            
            elif scanner == 'grype':
                matches = scanner_data.get('matches', [])
                for match in matches:
                    vulnerability = match.get('vulnerability', {})
                    if vulnerability.get('id') == finding.get('id'):
                        return match
            
            elif scanner == 'hadolint':
                # Hadolint findings are usually in a list
                if isinstance(scanner_data, list):
                    for item in scanner_data:
                        if item.get('message') == title or item.get('rule') == finding.get('id'):
                            return item
        
        return None
    
    def _generate_browser_html(self, findings: List[Dict[str, Any]], scan_id: str) -> str:
        """Generate main findings browser HTML using template."""
        
        # Group findings by various criteria
        by_severity = self._group_by_severity(findings)
        by_scanner = self._group_by_scanner(findings)
        by_target = self._group_by_target(findings)
        
        # Generate findings HTML and filter buttons
        findings_grid = self._generate_findings_grid(findings)
        severity_filters = self._generate_severity_filter_buttons(by_severity)
        scanner_filters = self._generate_scanner_filter_buttons(by_scanner)
        target_filters = self._generate_target_filter_buttons(by_target)
        
        # Ensure scan_id is not None or empty
        if not scan_id:
            scan_id = 'Unknown Scan'
        
        context = {
            'scan_id': scan_id,
            'total_findings': len(findings),
            'css_styles': template_loader.load_template('findings_browser.css'),
            'severity_filters': severity_filters,
            'scanner_filters': scanner_filters,
            'target_filters': target_filters,
            'findings_grid': findings_grid,
            'javascript': template_loader.load_template('javascript_findings.js')
        }
        
        return template_loader.render('findings_browser.html', context)
    
    def _generate_target_findings_html(self, findings: List[Dict[str, Any]], target_name: str) -> str:
        """Generate target-specific findings viewer HTML."""
        
        findings_grid = self._generate_findings_grid(findings)
        
        context = {
            'target_name': target_name,
            'total_findings': len(findings),
            'css_styles': template_loader.load_template('findings_browser.css'),
            'findings_grid': findings_grid,
            'javascript': template_loader.load_template('javascript_findings.js')
        }
        
        return template_loader.render('target_findings.html', context)
    
    def _group_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity."""
        groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in groups:
                groups[severity].append(finding)
            else:
                groups['info'].append(finding)
        
        return groups
    
    def _group_by_scanner(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by scanner."""
        groups = {}
        
        for finding in findings:
            scanner = finding.get('scanner', 'unknown')
            if scanner not in groups:
                groups[scanner] = []
            groups[scanner].append(finding)
        
        return groups
    
    def _group_by_target(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by target."""
        groups = {}
        
        for finding in findings:
            target = finding.get('target_name', 'unknown')
            if target not in groups:
                groups[target] = []
            groups[target].append(finding)
        
        return groups
    
    def _generate_severity_filter_buttons(self, by_severity: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate filter buttons for severities."""
        buttons = ""
        for severity, findings in sorted(by_severity.items()):
            buttons += f'<button class="btn btn-filter" data-filter-type="severity" data-filter-value="{severity}">{severity.title()} ({len(findings)})</button>'
        return buttons
    
    def _generate_scanner_filter_buttons(self, by_scanner: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate filter buttons for scanners."""
        buttons = ""
        for scanner, findings in sorted(by_scanner.items()):
            buttons += f'<button class="btn btn-filter" data-filter-type="scanner" data-filter-value="{scanner}">{scanner.title()} ({len(findings)})</button>'
        return buttons
    
    def _generate_target_filter_buttons(self, by_target: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate filter buttons for targets."""
        buttons = ""
        for target, findings in sorted(by_target.items()):
            buttons += f'<button class="btn btn-filter" data-filter-type="target" data-filter-value="{target}">{target} ({len(findings)})</button>'
        return buttons
    
    def _generate_findings_grid(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings grid HTML."""
        if not findings:
            return '<div class="no-findings">No findings to display.</div>'
        
        html = ""
        for finding in findings:
            severity = finding.get('severity', 'info')
            # Handle different possible target field names
            target_name = finding.get('target_name') or finding.get('target') or 'unknown'
            
            # Generate additional details from metadata
            additional_details = self._generate_additional_details(finding)
            
            # Use raw data if available, otherwise use the processed finding
            display_data = finding.get('raw_data', finding)
            
            # Prepare raw JSON data for the viewer (URL-encoded for safe HTML attribute)
            import urllib.parse
            import json
            raw_json = urllib.parse.quote(json.dumps(display_data))
            
            context = {
                'severity_class': severity.lower(),
                'severity': severity,
                'scanner': finding.get('scanner', 'unknown'),
                'target': target_name,
                'title': finding.get('title', 'Security Finding'),
                'location': finding.get('location', 'N/A'),
                'additional_details': additional_details,
                'raw_json': raw_json
            }
            html += template_loader.render('findings_grid.html', context)
        
        return html

    def _generate_additional_details(self, finding: Dict[str, Any]) -> str:
        """Generate additional details HTML from finding metadata."""
        html = ""
        
        # Add CVE information if available
        if finding.get('cve_id'):
            html += f'<p><strong>CVE ID:</strong> {finding["cve_id"]}</p>'
        
        # Add CVSS score if available
        if finding.get('cvss_score'):
            html += f'<p><strong>CVSS Score:</strong> {finding["cvss_score"]}</p>'
        
        # Add description if available and different from title
        description = finding.get('description', '')
        if description and description.lower() != 'no description available':
            truncated_desc = description[:200] + '...' if len(description) > 200 else description
            html += f'<p><strong>Description:</strong> {truncated_desc}</p>'
        
        # Add metadata alerts if available (for Dockle findings)
        if finding.get('metadata', {}).get('alerts'):
            alerts = finding['metadata']['alerts']
            if len(alerts) > 0:
                alert_text = alerts[0] if len(alerts) == 1 else f"{alerts[0]} (+{len(alerts)-1} more)"
                html += f'<p><strong>Details:</strong> {alert_text}</p>'
        
        # Add remediation if available
        if finding.get('remediation') and finding['remediation'] != 'Follow Docker security best practices':
            remediation = finding['remediation'][:150] + '...' if len(finding['remediation']) > 150 else finding['remediation']
            html += f'<p><strong>Remediation:</strong> {remediation}</p>'
        
        return html


def generate_all_findings_browsers(reports_dir: str = "reports") -> None:
    """Generate findings browsers for all existing scans."""
    generator = FindingsBrowserGenerator()
    reports_path = Path(reports_dir)
    
    if not reports_path.exists():
        return
    
    for scan_dir in reports_path.iterdir():
        if scan_dir.is_dir() and (scan_dir / "targets").exists():
            # Generate main findings browser
            generator.generate_findings_browser(scan_dir)
            
            # Generate target-specific viewers
            targets_dir = scan_dir / "targets"
            for target_dir in targets_dir.iterdir():
                if target_dir.is_dir():
                    generator.generate_target_findings_viewer(target_dir)