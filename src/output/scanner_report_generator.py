"""
Scanner HTML report generator.
Converts individual scanner JSON results to formatted HTML reports.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ScannerReportGenerator:
    """Generates HTML reports from scanner JSON files."""
    
    def __init__(self):
        self.css_styles = self._get_css_styles()
    
    def generate_scanner_report(self, scanner_file: Path, target_name: str) -> str:
        """Generate HTML report for a single scanner result."""
        try:
            with open(scanner_file, 'r') as f:
                scanner_data = json.load(f)
            
            scanner_name = scanner_file.stem
            html_content = self._generate_scanner_html(scanner_data, scanner_name, target_name)
            
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
    
    def _generate_scanner_html(self, scanner_data: Dict[str, Any], scanner_name: str, target_name: str) -> str:
        """Generate HTML content for scanner data."""
        
        # Extract findings from different possible structures
        findings = self._extract_findings(scanner_data)
        
        # Generate summary statistics
        stats = self._calculate_stats(findings)
        
        # Generate findings HTML
        findings_html = self._generate_findings_html(findings)
        
        # Generate metadata HTML
        metadata_html = self._generate_metadata_html(scanner_data)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔧 {scanner_name.title()} Report - {target_name}</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="breadcrumb">
                <a href="../../../../index.html">🏠 All Scans</a> / 
                <a href="../../../index.html">📊 Scan</a> / 
                <a href="../../index.html">🎯 {target_name}</a> / 
                <span>{scanner_name.title()}</span>
            </div>
            <h1>🔧 {scanner_name.title()} Scanner Report</h1>
            <div class="scan-meta">
                <p><strong>Target:</strong> {target_name}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Total Findings:</strong> {len(findings)}</p>
            </div>
        </header>
        
        <div class="summary-stats">
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="stat-number">{stats['total']}</div>
            </div>
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="stat-number">{stats['critical']}</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="stat-number">{stats['high']}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="stat-number">{stats['medium']}</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="stat-number">{stats['low']}</div>
            </div>
        </div>
        
        <div class="actions-bar">
            <button onclick="filterFindings('all')" class="btn btn-primary active" id="filter-all">All Findings</button>
            <button onclick="filterFindings('critical')" class="btn btn-critical" id="filter-critical">Critical</button>
            <button onclick="filterFindings('high')" class="btn btn-high" id="filter-high">High</button>
            <button onclick="filterFindings('medium')" class="btn btn-medium" id="filter-medium">Medium</button>
            <button onclick="filterFindings('low')" class="btn btn-low" id="filter-low">Low</button>
            <input type="text" id="search-input" placeholder="Search findings..." class="search-input">
        </div>
        
        <main class="main-content">
            <h2>🔍 Detailed Findings</h2>
            <div id="findings-container">
                {findings_html}
            </div>
            
            {metadata_html}
        </main>
        
        <footer class="footer">
            <p><a href="../../index.html">← Back to Target Overview</a></p>
        </footer>
    </div>
    
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""
        
        return html_content
    
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
        for i, finding in enumerate(findings):
            severity = self._get_severity(finding).lower()
            title = self._get_finding_title(finding)
            description = self._get_finding_description(finding)
            location = self._get_finding_location(finding)
            
            html += f"""
            <div class="finding-card severity-{severity}" data-severity="{severity}" data-index="{i}">
                <div class="finding-header">
                    <div class="finding-title">{title}</div>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                <div class="finding-content">
                    <div class="finding-description">{description}</div>
                    {f'<div class="finding-location"><strong>Location:</strong> {location}</div>' if location else ''}
                    <div class="finding-raw">
                        <button onclick="toggleRawData({i})" class="btn btn-outline btn-sm">Toggle Raw Data</button>
                        <pre class="raw-data" id="raw-{i}" style="display: none;">{json.dumps(finding, indent=2)}</pre>
                    </div>
                </div>
            </div>
            """
        
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
        metadata_items = []
        
        # Extract relevant metadata
        for key, value in scanner_data.items():
            if key not in ['findings', 'results', 'vulnerabilities', 'details', 'matches', 'artifacts', 'Results']:
                if isinstance(value, (str, int, float, bool)):
                    metadata_items.append((key, value))
        
        if not metadata_items:
            return ""
        
        metadata_html = '<div class="metadata-section"><h3>📊 Scanner Metadata</h3><div class="metadata-grid">'
        
        for key, value in metadata_items[:10]:  # Limit to 10 items
            metadata_html += f'<div class="metadata-item"><strong>{key}:</strong> {value}</div>'
        
        metadata_html += '</div></div>'
        
        return metadata_html
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for scanner reports."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; border-radius: 15px; margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .breadcrumb { margin-bottom: 15px; font-size: 0.9em; opacity: 0.8; }
        .breadcrumb a { color: white; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        
        .header h1 { font-size: 2.2em; margin-bottom: 15px; }
        .scan-meta p { margin-bottom: 5px; opacity: 0.9; }
        
        .summary-stats {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; margin-bottom: 20px;
        }
        
        .stat-card {
            background: white; padding: 20px; border-radius: 10px; text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); border-left: 5px solid #667eea;
        }
        
        .stat-card.critical { border-left-color: #dc3545; }
        .stat-card.high { border-left-color: #fd7e14; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #28a745; }
        
        .stat-card h3 { color: #666; margin-bottom: 10px; font-size: 0.9em; }
        .stat-number { font-size: 2em; font-weight: bold; color: #333; }
        
        .actions-bar {
            background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); display: flex; gap: 10px; flex-wrap: wrap;
            align-items: center;
        }
        
        .btn {
            padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer;
            font-size: 0.9em; font-weight: 500; transition: all 0.2s ease; text-decoration: none;
        }
        
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover, .btn-primary.active { background: #5a6fd8; }
        .btn-critical { background: #dc3545; color: white; }
        .btn-high { background: #fd7e14; color: white; }
        .btn-medium { background: #ffc107; color: #333; }
        .btn-low { background: #28a745; color: white; }
        .btn-outline { background: transparent; border: 1px solid #667eea; color: #667eea; }
        .btn-outline:hover { background: #667eea; color: white; }
        .btn-sm { padding: 4px 8px; font-size: 0.8em; }
        
        .search-input {
            flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid #ddd;
            border-radius: 6px; font-size: 0.9em;
        }
        
        .main-content {
            background: white; padding: 30px; border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1); margin-bottom: 20px;
        }
        
        .main-content h2 {
            margin-bottom: 25px; color: #333; border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .finding-card {
            border: 1px solid #e9ecef; border-radius: 10px; margin-bottom: 20px;
            background: #f8f9fa; overflow: hidden; transition: all 0.3s ease;
        }
        
        .finding-card:hover { box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        
        .finding-card.severity-critical { border-left: 5px solid #dc3545; }
        .finding-card.severity-high { border-left: 5px solid #fd7e14; }
        .finding-card.severity-medium { border-left: 5px solid #ffc107; }
        .finding-card.severity-low { border-left: 5px solid #28a745; }
        .finding-card.severity-info { border-left: 5px solid #17a2b8; }
        
        .finding-header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 15px 20px; background: white; border-bottom: 1px solid #e9ecef;
        }
        
        .finding-title { font-weight: bold; font-size: 1.1em; }
        
        .severity-badge {
            padding: 4px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 500;
            color: white;
        }
        
        .severity-badge.severity-critical { background: #dc3545; }
        .severity-badge.severity-high { background: #fd7e14; }
        .severity-badge.severity-medium { background: #ffc107; color: #333; }
        .severity-badge.severity-low { background: #28a745; }
        .severity-badge.severity-info { background: #17a2b8; }
        
        .finding-content { padding: 20px; }
        .finding-description { margin-bottom: 15px; line-height: 1.6; }
        .finding-location { margin-bottom: 15px; color: #666; font-size: 0.9em; }
        
        .raw-data {
            background: #f8f9fa; border: 1px solid #e9ecef; padding: 15px;
            border-radius: 5px; font-size: 0.8em; margin-top: 10px; overflow-x: auto;
        }
        
        .metadata-section {
            margin-top: 40px; padding-top: 20px; border-top: 2px solid #e9ecef;
        }
        
        .metadata-section h3 { margin-bottom: 20px; color: #333; }
        
        .metadata-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .metadata-item {
            padding: 15px; background: #f8f9fa; border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .no-findings {
            text-align: center; padding: 40px; color: #666; font-style: italic;
            background: #f8f9fa; border-radius: 10px;
        }
        
        .footer {
            text-align: center; padding: 20px; color: #666; font-size: 0.9em;
        }
        
        .footer a { color: #667eea; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
        
        .hidden { display: none !important; }
        
        @media (max-width: 768px) {
            .summary-stats { grid-template-columns: repeat(2, 1fr); }
            .actions-bar { flex-direction: column; align-items: stretch; }
            .search-input { min-width: 100%; }
        }
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactive functionality."""
        return """
        let currentFilter = 'all';
        
        function filterFindings(severity) {
            currentFilter = severity;
            const findings = document.querySelectorAll('.finding-card');
            const buttons = document.querySelectorAll('.actions-bar .btn');
            
            // Update button states
            buttons.forEach(btn => btn.classList.remove('active'));
            document.getElementById('filter-' + severity).classList.add('active');
            
            // Filter findings
            findings.forEach(finding => {
                if (severity === 'all' || finding.dataset.severity === severity) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
            
            updateVisibleCount();
        }
        
        function toggleRawData(index) {
            const rawData = document.getElementById('raw-' + index);
            rawData.style.display = rawData.style.display === 'none' ? 'block' : 'none';
        }
        
        function updateVisibleCount() {
            const visible = document.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            const total = document.querySelectorAll('.finding-card').length;
            
            // Update the findings header if it exists
            const header = document.querySelector('.main-content h2');
            if (header) {
                const baseText = '🔍 Detailed Findings';
                if (currentFilter === 'all') {
                    header.textContent = `${baseText} (${total})`;
                } else {
                    header.textContent = `${baseText} - ${currentFilter.toUpperCase()} (${visible}/${total})`;
                }
            }
        }
        
        // Search functionality
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const findings = document.querySelectorAll('.finding-card');
            
            findings.forEach(finding => {
                const title = finding.querySelector('.finding-title').textContent.toLowerCase();
                const description = finding.querySelector('.finding-description').textContent.toLowerCase();
                
                if (title.includes(searchTerm) || description.includes(searchTerm)) {
                    // Only show if it also matches the current severity filter
                    if (currentFilter === 'all' || finding.dataset.severity === currentFilter) {
                        finding.style.display = 'block';
                    }
                } else {
                    finding.style.display = 'none';
                }
            });
            
            updateVisibleCount();
        });
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            updateVisibleCount();
        });
        """