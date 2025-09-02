"""
Interactive findings browser generator.
Creates HTML interfaces for browsing and filtering security findings.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class FindingsBrowserGenerator:
    """Generates interactive HTML browsers for security findings."""
    
    def __init__(self):
        self.css_styles = self._get_css_styles()
    
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
        
        if not targets_dir.exists():
            return all_findings
        
        for target_dir in targets_dir.iterdir():
            if target_dir.is_dir():
                combined_file = target_dir / "combined_findings.json"
                if combined_file.exists():
                    try:
                        with open(combined_file, 'r') as f:
                            findings = json.load(f)
                            # Add target information to each finding
                            for finding in findings:
                                finding['target_name'] = target_dir.name
                                all_findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to load findings from {combined_file}: {e}")
        
        return all_findings
    
    def _generate_browser_html(self, findings: List[Dict[str, Any]], scan_id: str) -> str:
        """Generate main findings browser HTML."""
        
        # Calculate statistics
        stats = self._calculate_stats(findings)
        
        # Group findings by various criteria
        by_severity = self._group_by_severity(findings)
        by_scanner = self._group_by_scanner(findings)
        by_target = self._group_by_target(findings)
        
        # Generate findings HTML
        findings_html = self._generate_findings_grid(findings)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Findings Browser - {scan_id}</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="breadcrumb">
                <a href="../index.html">🏠 All Scans</a> / 
                <a href="index.html">📊 {scan_id}</a> / 
                <span>🔍 Findings Browser</span>
            </div>
            <h1>🔍 Security Findings Browser</h1>
            <div class="scan-meta">
                <p><strong>Scan ID:</strong> {scan_id}</p>
                <p><strong>Total Findings:</strong> {len(findings)}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stats-grid">
                <div class="stat-card total">
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
                <div class="stat-card info">
                    <h3>Info</h3>
                    <div class="stat-number">{stats['info']}</div>
                </div>
            </div>
        </div>
        
        <div class="filters-section">
            <div class="filter-group">
                <h4>🎚️ Filter by Severity</h4>
                <div class="filter-buttons">
                    <button onclick="filterBySeverity('all')" class="btn btn-primary active" id="sev-all">All ({stats['total']})</button>
                    <button onclick="filterBySeverity('critical')" class="btn btn-critical" id="sev-critical">Critical ({stats['critical']})</button>
                    <button onclick="filterBySeverity('high')" class="btn btn-high" id="sev-high">High ({stats['high']})</button>
                    <button onclick="filterBySeverity('medium')" class="btn btn-medium" id="sev-medium">Medium ({stats['medium']})</button>
                    <button onclick="filterBySeverity('low')" class="btn btn-low" id="sev-low">Low ({stats['low']})</button>
                    <button onclick="filterBySeverity('info')" class="btn btn-info" id="sev-info">Info ({stats['info']})</button>
                </div>
            </div>
            
            <div class="filter-group">
                <h4>🔧 Filter by Scanner</h4>
                <div class="filter-buttons">
                    <button onclick="filterByScanner('all')" class="btn btn-secondary active" id="scan-all">All Scanners</button>
                    {self._generate_scanner_buttons(by_scanner)}
                </div>
            </div>
            
            <div class="filter-group">
                <h4>🎯 Filter by Target</h4>
                <div class="filter-buttons">
                    <button onclick="filterByTarget('all')" class="btn btn-secondary active" id="tgt-all">All Targets</button>
                    {self._generate_target_buttons(by_target)}
                </div>
            </div>
            
            <div class="search-section">
                <h4>🔎 Search Findings</h4>
                <div class="search-controls">
                    <input type="text" id="search-input" placeholder="Search in titles, descriptions, locations..." class="search-input">
                    <button onclick="clearSearch()" class="btn btn-outline">Clear</button>
                    <button onclick="exportFiltered()" class="btn btn-primary">📥 Export Filtered</button>
                </div>
            </div>
        </div>
        
        <main class="main-content">
            <div class="results-header">
                <h2 id="results-title">🔍 All Findings ({len(findings)})</h2>
                <div class="view-controls">
                    <button onclick="toggleView('grid')" class="btn btn-outline active" id="view-grid">Grid View</button>
                    <button onclick="toggleView('list')" class="btn btn-outline" id="view-list">List View</button>
                </div>
            </div>
            
            <div id="findings-container" class="findings-grid">
                {findings_html}
            </div>
            
            <div id="no-results" class="no-results" style="display: none;">
                <h3>No findings match your current filters</h3>
                <p>Try adjusting your filters or search terms</p>
            </div>
        </main>
        
        <footer class="footer">
            <p><a href="index.html">← Back to Scan Overview</a></p>
        </footer>
    </div>
    
    <script>
        {self._get_browser_javascript(findings)}
    </script>
</body>
</html>"""
        
        return html_content
    
    def _generate_target_findings_html(self, findings: List[Dict[str, Any]], target_name: str) -> str:
        """Generate target-specific findings viewer HTML."""
        
        stats = self._calculate_stats(findings)
        findings_html = self._generate_findings_grid(findings)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎯 Target Findings - {target_name}</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="breadcrumb">
                <a href="../../../index.html">🏠 All Scans</a> / 
                <a href="../../index.html">📊 Scan</a> / 
                <a href="../index.html">🎯 {target_name}</a> / 
                <span>🔍 Findings</span>
            </div>
            <h1>🎯 Target Findings: {target_name}</h1>
            <div class="scan-meta">
                <p><strong>Total Findings:</strong> {len(findings)}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stats-grid">
                <div class="stat-card total">
                    <h3>Total</h3>
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
        </div>
        
        <div class="filters-section">
            <div class="filter-group">
                <h4>🎚️ Filter & Search</h4>
                <div class="search-controls">
                    <input type="text" id="search-input" placeholder="Search findings..." class="search-input">
                    <select id="severity-filter" class="filter-select">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                    <button onclick="clearFilters()" class="btn btn-outline">Clear</button>
                </div>
            </div>
        </div>
        
        <main class="main-content">
            <h2 id="results-title">🔍 All Findings ({len(findings)})</h2>
            <div id="findings-container" class="findings-grid">
                {findings_html}
            </div>
        </main>
        
        <footer class="footer">
            <p><a href="../index.html">← Back to Target Overview</a></p>
        </footer>
    </div>
    
    <script>
        {self._get_target_javascript(findings)}
    </script>
</body>
</html>"""
        
        return html_content
    
    def _calculate_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate statistics from findings."""
        stats = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] += 1
            else:
                stats['info'] += 1
        
        return stats
    
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
    
    def _generate_scanner_buttons(self, by_scanner: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate filter buttons for scanners."""
        buttons = ""
        for scanner, findings in sorted(by_scanner.items()):
            buttons += f'<button onclick="filterByScanner(\'{scanner}\')" class="btn btn-secondary" id="scan-{scanner}">{scanner.title()} ({len(findings)})</button>'
        return buttons
    
    def _generate_target_buttons(self, by_target: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate filter buttons for targets."""
        buttons = ""
        for target, findings in sorted(by_target.items()):
            buttons += f'<button onclick="filterByTarget(\'{target}\')" class="btn btn-secondary" id="tgt-{target}">{target} ({len(findings)})</button>'
        return buttons
    
    def _generate_findings_grid(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings grid HTML."""
        if not findings:
            return '<div class="no-findings">No findings to display.</div>'
        
        html = ""
        for i, finding in enumerate(findings):
            severity = finding.get('severity', 'info').lower()
            title = finding.get('title', 'Security Finding')
            description = finding.get('description', 'No description available')
            scanner = finding.get('scanner', 'unknown')
            location = finding.get('location', '')
            target = finding.get('target_name', '')
            remediation = finding.get('remediation', '')
            
            html += f"""
            <div class="finding-card severity-{severity}" data-severity="{severity}" data-scanner="{scanner}" data-target="{target}" data-index="{i}">
                <div class="finding-header">
                    <div class="finding-title">{title}</div>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                <div class="finding-content">
                    <div class="finding-meta">
                        <span class="meta-item">🔧 {scanner}</span>
                        {f'<span class="meta-item">🎯 {target}</span>' if target else ''}
                        {f'<span class="meta-item">📍 {location}</span>' if location else ''}
                    </div>
                    <div class="finding-description">{description}</div>
                    {f'<div class="finding-remediation"><strong>Remediation:</strong> {remediation}</div>' if remediation else ''}
                    <div class="finding-actions">
                        <button onclick="toggleDetails({i})" class="btn btn-outline btn-sm">Toggle Details</button>
                        <button onclick="exportFinding({i})" class="btn btn-outline btn-sm">Export</button>
                    </div>
                    <div class="finding-details" id="details-{i}" style="display: none;">
                        <pre class="finding-raw">{json.dumps(finding, indent=2)}</pre>
                    </div>
                </div>
            </div>
            """
        
        return html
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for findings browser."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh; color: #333;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
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
        
        .dashboard {
            background: white; padding: 25px; border-radius: 15px; margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .stat-card {
            padding: 20px; border-radius: 10px; text-align: center;
            border-left: 5px solid #667eea; background: #f8f9fa;
        }
        
        .stat-card.total { border-left-color: #667eea; }
        .stat-card.critical { border-left-color: #dc3545; }
        .stat-card.high { border-left-color: #fd7e14; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #28a745; }
        .stat-card.info { border-left-color: #17a2b8; }
        
        .stat-card h3 { color: #666; margin-bottom: 10px; font-size: 0.9em; }
        .stat-number { font-size: 1.8em; font-weight: bold; color: #333; }
        
        .filters-section {
            background: white; padding: 25px; border-radius: 15px; margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .filter-group { margin-bottom: 25px; }
        .filter-group:last-child { margin-bottom: 0; }
        .filter-group h4 { margin-bottom: 15px; color: #333; }
        
        .filter-buttons { display: flex; gap: 10px; flex-wrap: wrap; }
        
        .btn {
            padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer;
            font-size: 0.9em; font-weight: 500; transition: all 0.2s ease;
            text-decoration: none; display: inline-block;
        }
        
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover, .btn-primary.active { background: #5a6fd8; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover, .btn-secondary.active { background: #5a6268; }
        .btn-critical { background: #dc3545; color: white; }
        .btn-high { background: #fd7e14; color: white; }
        .btn-medium { background: #ffc107; color: #333; }
        .btn-low { background: #28a745; color: white; }
        .btn-info { background: #17a2b8; color: white; }
        .btn-outline { background: transparent; border: 1px solid #667eea; color: #667eea; }
        .btn-outline:hover { background: #667eea; color: white; }
        .btn-sm { padding: 6px 12px; font-size: 0.8em; }
        
        .search-section { margin-top: 25px; }
        .search-controls { display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }
        .search-input, .filter-select {
            flex: 1; min-width: 200px; padding: 10px 15px; border: 1px solid #ddd;
            border-radius: 8px; font-size: 0.95em;
        }
        
        .main-content {
            background: white; padding: 30px; border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1); margin-bottom: 20px;
        }
        
        .results-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 25px; padding-bottom: 15px; border-bottom: 2px solid #e9ecef;
        }
        
        .results-header h2 { color: #333; }
        .view-controls { display: flex; gap: 10px; }
        
        .findings-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .findings-list .finding-card { margin-bottom: 15px; }
        
        .finding-card {
            border: 1px solid #e9ecef; border-radius: 12px; background: #fff;
            overflow: hidden; transition: all 0.3s ease;
        }
        
        .finding-card:hover { box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        
        .finding-card.severity-critical { border-left: 5px solid #dc3545; }
        .finding-card.severity-high { border-left: 5px solid #fd7e14; }
        .finding-card.severity-medium { border-left: 5px solid #ffc107; }
        .finding-card.severity-low { border-left: 5px solid #28a745; }
        .finding-card.severity-info { border-left: 5px solid #17a2b8; }
        
        .finding-header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #e9ecef;
        }
        
        .finding-title { font-weight: 600; font-size: 1.05em; }
        
        .severity-badge {
            padding: 4px 10px; border-radius: 12px; font-size: 0.75em;
            font-weight: 600; color: white;
        }
        
        .severity-badge.severity-critical { background: #dc3545; }
        .severity-badge.severity-high { background: #fd7e14; }
        .severity-badge.severity-medium { background: #ffc107; color: #333; }
        .severity-badge.severity-low { background: #28a745; }
        .severity-badge.severity-info { background: #17a2b8; }
        
        .finding-content { padding: 20px; }
        .finding-meta { display: flex; gap: 15px; margin-bottom: 15px; flex-wrap: wrap; }
        .meta-item { font-size: 0.85em; color: #666; }
        .finding-description { margin-bottom: 15px; line-height: 1.6; }
        .finding-remediation { margin-bottom: 15px; padding: 12px; background: #e7f3ff; border-radius: 6px; font-size: 0.9em; }
        .finding-actions { display: flex; gap: 10px; margin-bottom: 15px; }
        .finding-details { margin-top: 15px; }
        .finding-raw { background: #f8f9fa; padding: 15px; border-radius: 6px; font-size: 0.8em; overflow-x: auto; max-height: 300px; overflow-y: auto; }
        
        .no-results {
            text-align: center; padding: 60px; color: #666;
            background: #f8f9fa; border-radius: 12px;
        }
        
        .no-results h3 { margin-bottom: 10px; }
        .no-findings { text-align: center; padding: 40px; color: #666; font-style: italic; }
        
        .footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
        .footer a { color: #667eea; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
        
        .hidden { display: none !important; }
        
        @media (max-width: 768px) {
            .findings-grid { grid-template-columns: 1fr; }
            .filter-buttons, .search-controls { flex-direction: column; }
            .results-header { flex-direction: column; align-items: stretch; gap: 15px; }
        }
        """
    
    def _get_browser_javascript(self, findings: List[Dict[str, Any]]) -> str:
        """Get JavaScript for the main findings browser."""
        return f"""
        let allFindings = {json.dumps(findings)};
        let filteredFindings = [...allFindings];
        let currentFilters = {{ severity: 'all', scanner: 'all', target: 'all', search: '' }};
        let currentView = 'grid';
        
        function filterBySeverity(severity) {{
            currentFilters.severity = severity;
            updateActiveButton('sev-', severity);
            applyFilters();
        }}
        
        function filterByScanner(scanner) {{
            currentFilters.scanner = scanner;
            updateActiveButton('scan-', scanner);
            applyFilters();
        }}
        
        function filterByTarget(target) {{
            currentFilters.target = target;
            updateActiveButton('tgt-', target);
            applyFilters();
        }}
        
        function updateActiveButton(prefix, value) {{
            document.querySelectorAll(`[id^="${{prefix}}"]`).forEach(btn => btn.classList.remove('active'));
            document.getElementById(prefix + value).classList.add('active');
        }}
        
        function applyFilters() {{
            filteredFindings = allFindings.filter(finding => {{
                let matchSeverity = currentFilters.severity === 'all' || 
                                  (finding.severity || 'info').toLowerCase() === currentFilters.severity;
                let matchScanner = currentFilters.scanner === 'all' || 
                                 (finding.scanner || 'unknown') === currentFilters.scanner;
                let matchTarget = currentFilters.target === 'all' || 
                                (finding.target_name || 'unknown') === currentFilters.target;
                let matchSearch = !currentFilters.search || 
                                matchesSearch(finding, currentFilters.search);
                
                return matchSeverity && matchScanner && matchTarget && matchSearch;
            }});
            
            updateDisplay();
        }}
        
        function matchesSearch(finding, searchTerm) {{
            const searchLower = searchTerm.toLowerCase();
            const title = (finding.title || '').toLowerCase();
            const description = (finding.description || '').toLowerCase();
            const location = (finding.location || '').toLowerCase();
            
            return title.includes(searchLower) || 
                   description.includes(searchLower) || 
                   location.includes(searchLower);
        }}
        
        function updateDisplay() {{
            const container = document.getElementById('findings-container');
            const noResults = document.getElementById('no-results');
            const resultsTitle = document.getElementById('results-title');
            
            if (filteredFindings.length === 0) {{
                container.style.display = 'none';
                noResults.style.display = 'block';
                resultsTitle.textContent = '🔍 No findings match your filters';
            }} else {{
                container.style.display = currentView === 'grid' ? 'grid' : 'block';
                noResults.style.display = 'none';
                resultsTitle.textContent = `🔍 Showing ${{filteredFindings.length}} of ${{allFindings.length}} findings`;
                
                // Show/hide finding cards
                const allCards = document.querySelectorAll('.finding-card');
                allCards.forEach(card => {{
                    const index = parseInt(card.dataset.index);
                    const finding = allFindings[index];
                    const shouldShow = filteredFindings.includes(finding);
                    card.style.display = shouldShow ? 'block' : 'none';
                }});
            }}
        }}
        
        function toggleView(view) {{
            currentView = view;
            const container = document.getElementById('findings-container');
            const gridBtn = document.getElementById('view-grid');
            const listBtn = document.getElementById('view-list');
            
            if (view === 'grid') {{
                container.className = 'findings-grid';
                gridBtn.classList.add('active');
                listBtn.classList.remove('active');
            }} else {{
                container.className = 'findings-list';
                listBtn.classList.add('active');
                gridBtn.classList.remove('active');
            }}
        }}
        
        function toggleDetails(index) {{
            const details = document.getElementById('details-' + index);
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
        
        function exportFinding(index) {{
            const finding = allFindings[index];
            const dataStr = JSON.stringify(finding, null, 2);
            const dataBlob = new Blob([dataStr], {{type: 'application/json'}});
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `finding_${{finding.title || 'unknown'}}.json`;
            link.click();
            
            URL.revokeObjectURL(url);
        }}
        
        function exportFiltered() {{
            const dataStr = JSON.stringify(filteredFindings, null, 2);
            const dataBlob = new Blob([dataStr], {{type: 'application/json'}});
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = 'filtered_findings.json';
            link.click();
            
            URL.revokeObjectURL(url);
        }}
        
        function clearSearch() {{
            document.getElementById('search-input').value = '';
            currentFilters.search = '';
            applyFilters();
        }}
        
        // Event listeners
        document.getElementById('search-input').addEventListener('input', function(e) {{
            currentFilters.search = e.target.value;
            applyFilters();
        }});
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            updateDisplay();
        }});
        """
    
    def _get_target_javascript(self, findings: List[Dict[str, Any]]) -> str:
        """Get JavaScript for target findings viewer."""
        return f"""
        let allFindings = {json.dumps(findings)};
        
        function clearFilters() {{
            document.getElementById('search-input').value = '';
            document.getElementById('severity-filter').value = 'all';
            showAllFindings();
        }}
        
        function showAllFindings() {{
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => card.style.display = 'block');
            updateResultsTitle(allFindings.length, allFindings.length);
        }}
        
        function updateResultsTitle(shown, total) {{
            const title = document.getElementById('results-title');
            if (shown === total) {{
                title.textContent = `🔍 All Findings (${{total}})`;
            }} else {{
                title.textContent = `🔍 Showing ${{shown}} of ${{total}} findings`;
            }}
        }}
        
        function filterFindings() {{
            const searchTerm = document.getElementById('search-input').value.toLowerCase();
            const severityFilter = document.getElementById('severity-filter').value;
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            cards.forEach(card => {{
                const title = card.querySelector('.finding-title').textContent.toLowerCase();
                const description = card.querySelector('.finding-description').textContent.toLowerCase();
                const severity = card.dataset.severity;
                
                const matchesSearch = !searchTerm || title.includes(searchTerm) || description.includes(searchTerm);
                const matchesSeverity = severityFilter === 'all' || severity === severityFilter;
                
                if (matchesSearch && matchesSeverity) {{
                    card.style.display = 'block';
                    visibleCount++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});
            
            updateResultsTitle(visibleCount, allFindings.length);
        }}
        
        function toggleDetails(index) {{
            const details = document.getElementById('details-' + index);
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
        
        function exportFinding(index) {{
            const finding = allFindings[index];
            const dataStr = JSON.stringify(finding, null, 2);
            const dataBlob = new Blob([dataStr], {{type: 'application/json'}});
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `finding_${{finding.title || 'unknown'}}.json`;
            link.click();
            
            URL.revokeObjectURL(url);
        }}
        
        // Event listeners
        document.getElementById('search-input').addEventListener('input', filterFindings);
        document.getElementById('severity-filter').addEventListener('change', filterFindings);
        """


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