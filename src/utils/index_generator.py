
"""
Automatic index.html generator for security scan reports.
Generates hierarchical index pages for better navigation.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ReportIndexGenerator:
    """Generates index.html files for scan reports."""
    
    def __init__(self, reports_base_dir: str = "reports"):
        """
        Initialize the index generator.
        
        Args:
            reports_base_dir: Base directory containing all scan reports
        """
        self.reports_base_dir = Path(reports_base_dir)
        self.css_styles = self._get_css_styles()
    
    def generate_all_indexes(self) -> None:
        """Generate all index files in the reports directory."""
        try:
            # Generate main reports index
            self.generate_main_index()
            
            # Generate index for each scan directory
            for scan_dir in self._get_scan_directories():
                self.generate_scan_index(scan_dir)
                
                # Generate target indexes within each scan
                targets_dir = scan_dir / "targets"
                if targets_dir.exists():
                    for target_dir in targets_dir.iterdir():
                        if target_dir.is_dir():
                            self.generate_target_index(target_dir)
            
            logger.info("Successfully generated all index files")
            
        except Exception as e:
            logger.error(f"Failed to generate index files: {e}")
            raise
    
    def generate_main_index(self) -> None:
        """Generate the main reports/index.html file."""
        scan_dirs = self._get_scan_directories()
        scan_summaries = []
        
        for scan_dir in sorted(scan_dirs, key=lambda x: x.name, reverse=True):
            summary = self._get_scan_summary(scan_dir)
            scan_summaries.append(summary)
        
        html_content = self._generate_main_index_html(scan_summaries)
        index_file = self.reports_base_dir / "index.html"
        
        self._write_html_file(index_file, html_content)
        logger.info(f"Generated main index: {index_file}")
    
    def generate_scan_index(self, scan_dir: Path) -> None:
        """Generate index.html for a specific scan directory."""
        scan_summary = self._get_scan_summary(scan_dir)
        targets_summary = self._get_targets_summary(scan_dir)
        
        html_content = self._generate_scan_index_html(scan_summary, targets_summary)
        index_file = scan_dir / "index.html"
        
        self._write_html_file(index_file, html_content)
        logger.info(f"Generated scan index: {index_file}")
    
    def generate_target_index(self, target_dir: Path) -> None:
        """Generate index.html for a specific target directory."""
        target_summary = self._get_target_summary(target_dir)
        scanners_summary = self._get_scanners_summary(target_dir)
        
        html_content = self._generate_target_index_html(target_summary, scanners_summary)
        index_file = target_dir / "index.html"
        
        self._write_html_file(index_file, html_content)
        logger.info(f"Generated target index: {index_file}")
    
    def _get_scan_directories(self) -> List[Path]:
        """Get all scan directories in the reports folder."""
        if not self.reports_base_dir.exists():
            return []
        
        scan_dirs = []
        for item in self.reports_base_dir.iterdir():
            if item.is_dir() and self._is_scan_directory(item):
                scan_dirs.append(item)
        
        return scan_dirs
    
    def _is_scan_directory(self, path: Path) -> bool:
        """Check if a directory is a scan directory based on naming pattern."""
        name = path.name
        
        # Check for common scan directory patterns
        scan_patterns = (
            "security-scan-",
            "container-", 
            "git-", 
            "k8s-", 
            "terraform-", 
            "filesystem-",
            "scan-"
        )
        
        # First check if it starts with known scan patterns
        if name.startswith(scan_patterns):
            return True
        
        # Check for pure timestamp pattern: YYYY-MM-DD_HH-MM-SS
        try:
            datetime.strptime(name, "%Y-%m-%d_%H-%M-%S")
            return True
        except ValueError:
            pass
        
        # Check if it contains timestamp at the end
        if "_" in name:
            timestamp_part = name.split("_")[-2] + "_" + name.split("_")[-1]
            try:
                datetime.strptime(timestamp_part, "%Y-%m-%d_%H-%M-%S")
                return True
            except (ValueError, IndexError):
                pass
        
        # Check if directory contains scan-like structure
        if (path / "targets").exists() or (path / "summary").exists() or (path / "raw-data").exists():
            return True
        
        return False
    
    def _get_scan_summary(self, scan_dir: Path) -> Dict[str, Any]:
        """Get summary information for a scan directory."""
        metadata_file = scan_dir / "metadata" / "scan_metadata.json"
        summary = {
            "scan_id": scan_dir.name,
            "scan_dir": scan_dir.name,
            "timestamp": self._parse_timestamp_from_name(scan_dir.name),
            "targets_count": 0,
            "total_findings": 0,
            "scanners_used": [],
            "scan_type": "unknown",
            "description": ""
        }
        
        # Load metadata if available
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    summary.update(metadata)
            except Exception as e:
                logger.warning(f"Failed to load metadata from {metadata_file}: {e}")
        
        # Count targets
        targets_dir = scan_dir / "targets"
        if targets_dir.exists():
            summary["targets_count"] = len([d for d in targets_dir.iterdir() if d.is_dir()])
        
        # Get scanners used and total findings
        summary.update(self._analyze_scan_results(scan_dir))
        
        return summary
    
    def _get_targets_summary(self, scan_dir: Path) -> List[Dict[str, Any]]:
        """Get summary of all targets in a scan."""
        targets_dir = scan_dir / "targets"
        if not targets_dir.exists():
            return []
        
        targets = []
        for target_dir in targets_dir.iterdir():
            if target_dir.is_dir():
                target_summary = self._get_target_summary(target_dir)
                targets.append(target_summary)
        
        return sorted(targets, key=lambda x: x["name"])
    
    def _get_target_summary(self, target_dir: Path) -> Dict[str, Any]:
        """Get summary information for a target."""
        combined_findings_file = target_dir / "combined_findings.json"
        
        summary = {
            "name": target_dir.name,
            "path": str(target_dir),
            "scanners_count": 0,
            "total_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "scanners": []
        }
        
        # Count scanners
        scanners_dir = target_dir / "scanners"
        if scanners_dir.exists():
            scanners = [f.stem for f in scanners_dir.iterdir() if f.is_file() and f.suffix == '.json']
            summary["scanners"] = scanners
            summary["scanners_count"] = len(scanners)
        
        # Load combined findings if available
        if combined_findings_file.exists():
            try:
                with open(combined_findings_file, 'r') as f:
                    findings = json.load(f)
                    summary["total_findings"] = len(findings)
                    
                    # Count by severity
                    for finding in findings:
                        severity = finding.get("severity", "INFO").upper()
                        if severity in summary["severity_counts"]:
                            summary["severity_counts"][severity] += 1
            except Exception as e:
                logger.warning(f"Failed to load findings from {combined_findings_file}: {e}")
        
        return summary
    
    def _get_scanners_summary(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Get summary of all scanners for a target."""
        scanners_dir = target_dir / "scanners"
        if not scanners_dir.exists():
            return []
        
        scanners = []
        for scanner_file in scanners_dir.iterdir():
            if scanner_file.is_file() and scanner_file.suffix == '.json':
                scanner_name = scanner_file.stem
                scanner_summary = {
                    "name": scanner_name,
                    "findings_count": 0,
                    "has_report": False,  # Will be generated dynamically
                    "has_findings": True,  # JSON file exists
                    "has_raw": True,  # JSON contains raw data
                    "json_file": scanner_file.name
                }
                
                # Count findings from the JSON file
                try:
                    with open(scanner_file, 'r') as f:
                        scanner_data = json.load(f)
                        if isinstance(scanner_data, dict) and 'findings' in scanner_data:
                            findings = scanner_data['findings']
                            scanner_summary["findings_count"] = len(findings) if isinstance(findings, list) else 0
                        elif isinstance(scanner_data, list):
                            scanner_summary["findings_count"] = len(scanner_data)
                except Exception as e:
                    logger.warning(f"Failed to load scanner data from {scanner_file}: {e}")
                
                scanners.append(scanner_summary)
        
        return sorted(scanners, key=lambda x: x["name"])
    
    def _analyze_scan_results(self, scan_dir: Path) -> Dict[str, Any]:
        """Analyze scan results to get summary statistics."""
        scanners_used = set()
        total_findings = 0
        
        targets_dir = scan_dir / "targets"
        if targets_dir.exists():
            for target_dir in targets_dir.iterdir():
                if target_dir.is_dir():
                    scanners_dir = target_dir / "scanners"
                    if scanners_dir.exists():
                        for scanner_file in scanners_dir.iterdir():
                            if scanner_file.is_file() and scanner_file.suffix == '.json':
                                scanners_used.add(scanner_file.stem)
                                
                                # Count findings from scanner JSON file
                                try:
                                    with open(scanner_file, 'r') as f:
                                        scanner_data = json.load(f)
                                        if isinstance(scanner_data, dict) and 'findings' in scanner_data:
                                            findings = scanner_data['findings']
                                            if isinstance(findings, list):
                                                total_findings += len(findings)
                                        elif isinstance(scanner_data, list):
                                            total_findings += len(scanner_data)
                                except Exception:
                                    pass
        
        return {
            "scanners_used": sorted(list(scanners_used)),
            "total_findings": total_findings
        }
    
    def _parse_timestamp_from_name(self, name: str) -> str:
        """Parse timestamp from directory name."""
        try:
            # Try new format: YYYY-MM-DD_HH-MM-SS
            dt = datetime.strptime(name, "%Y-%m-%d_%H-%M-%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Try old format patterns
            if "-" in name:
                parts = name.split("-")
                if len(parts) >= 3:
                    return f"{parts[-2]}-{parts[-1]}"
            return name
    
    def _generate_main_index_html(self, scan_summaries: List[Dict[str, Any]]) -> str:
        """Generate HTML for main index page."""
        scans_html = ""
        
        if not scan_summaries:
            scans_html = '<div class="no-scans">No scan reports found.</div>'
        else:
            for scan in scan_summaries:
                scans_html += f"""
                <div class="scan-card">
                    <div class="scan-header">
                        <h3><a href="{scan['scan_dir']}/index.html">📊 {scan['scan_id']}</a></h3>
                        <span class="timestamp">{scan['timestamp']}</span>
                    </div>
                    <div class="scan-stats">
                        <div class="stat">
                            <span class="stat-label">Targets:</span>
                            <span class="stat-value">{scan['targets_count']}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Findings:</span>
                            <span class="stat-value">{scan['total_findings']}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Scanners:</span>
                            <span class="stat-value">{len(scan['scanners_used'])}</span>
                        </div>
                    </div>
                    <div class="scanners-used">
                        <strong>Scanners:</strong> {', '.join(scan['scanners_used']) if scan['scanners_used'] else 'None'}
                    </div>
                    {f'<div class="description">{scan["description"]}</div>' if scan.get("description") else ''}
                    <div class="scan-actions">
                        <a href="{scan['scan_dir']}/summary/executive_summary.html" class="btn btn-primary">📋 Executive Summary</a>
                        <a href="{scan['scan_dir']}/summary/detailed_report.html" class="btn btn-secondary">📄 Detailed Report</a>
                        <a href="{scan['scan_dir']}/findings-browser.html" class="btn btn-primary">🔍 Browse Findings</a>
                        <a href="{scan['scan_dir']}/index.html" class="btn btn-outline">🔍 Browse Results</a>
                    </div>
                </div>
                """
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Security Scanner Reports</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Security Scanner Reports</h1>
            <p class="subtitle">Comprehensive security analysis results</p>
            <div class="header-stats">
                <div class="stat">
                    <span class="stat-value">{len(scan_summaries)}</span>
                    <span class="stat-label">Total Scans</span>
                </div>
                <div class="stat">
                    <span class="stat-value">{sum(s['targets_count'] for s in scan_summaries)}</span>
                    <span class="stat-label">Targets Analyzed</span>
                </div>
                <div class="stat">
                    <span class="stat-value">{sum(s['total_findings'] for s in scan_summaries)}</span>
                    <span class="stat-label">Total Findings</span>
                </div>
            </div>
        </header>
        
        <main class="main-content">
            <div class="scans-grid">
                {scans_html}
            </div>
        </main>
        
        <footer class="footer">
            <p>Generated by Security Scanner | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>"""
    
    def _generate_scan_index_html(self, scan_summary: Dict[str, Any], targets_summary: List[Dict[str, Any]]) -> str:
        """Generate HTML for scan index page."""
        targets_html = ""
        
        if not targets_summary:
            targets_html = '<div class="no-targets">No targets found in this scan.</div>'
        else:
            for target in targets_summary:
                severity_badges = self._generate_severity_badges(target["severity_counts"])
                targets_html += f"""
                <div class="target-card">
                    <div class="target-header">
                        <h4><a href="targets/{target['name']}/index.html">🎯 {target['name']}</a></h4>
                        <span class="findings-count">{target['total_findings']} findings</span>
                    </div>
                    <div class="severity-badges">
                        {severity_badges}
                    </div>
                    <div class="scanners-list">
                        <strong>Scanners:</strong> {', '.join(target['scanners']) if target['scanners'] else 'None'}
                    </div>
                    <div class="target-actions">
                        <a href="targets/{target['name']}/index.html" class="btn btn-primary">🔍 View Details</a>
                        <a href="targets/{target['name']}/findings.html" class="btn btn-secondary">🔍 Browse Findings</a>
                        <a href="targets/{target['name']}/combined_findings.json" class="btn btn-outline">📄 JSON Report</a>
                    </div>
                </div>
                """
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📊 Scan Report - {scan_summary['scan_id']}</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="breadcrumb">
                <a href="../index.html">🏠 All Scans</a> / <span>{scan_summary['scan_id']}</span>
            </div>
            <h1>📊 Scan Report: {scan_summary['scan_id']}</h1>
            <div class="scan-meta">
                <p><strong>Timestamp:</strong> {scan_summary['timestamp']}</p>
                <p><strong>Targets:</strong> {scan_summary['targets_count']}</p>
                <p><strong>Total Findings:</strong> {scan_summary['total_findings']}</p>
                <p><strong>Scanners Used:</strong> {', '.join(scan_summary['scanners_used']) if scan_summary['scanners_used'] else 'None'}</p>
            </div>
        </header>
        
                <div class="summary-actions">
            <a href="summary/executive_summary.html" class="btn btn-primary">📋 Executive Summary</a>
            <a href="summary/detailed_report.html" class="btn btn-secondary">📄 Detailed Report</a>
            <a href="findings-browser.html" class="btn btn-primary">🔍 Browse Findings</a>
            <a href="raw-data/{scan_summary['scan_id']}_findings.json" class="btn btn-outline">📊 JSON Summary</a>
            <a href="raw-data/{scan_summary['scan_id']}.sarif" class="btn btn-outline">🔧 SARIF Report</a>
        </div></search>
</search_and_replace>
        
        <main class="main-content">
            <h2>🎯 Scan Targets</h2>
            <div class="targets-grid">
                {targets_html}
            </div>
        </main>
        
        <footer class="footer">
            <p><a href="../index.html">← Back to All Scans</a></p>
        </footer>
    </div>
</body>
</html>"""
    
    def _generate_target_index_html(self, target_summary: Dict[str, Any], scanners_summary: List[Dict[str, Any]]) -> str:
        """Generate HTML for target index page."""
        scanners_html = ""
        
        if not scanners_summary:
            scanners_html = '<div class="no-scanners">No scanner results found for this target.</div>'
        else:
            for scanner in scanners_summary:
                status_badges = []
                if scanner["has_report"]:
                    status_badges.append('<span class="badge badge-success">HTML Report</span>')
                if scanner["has_findings"]:
                    status_badges.append('<span class="badge badge-info">JSON Findings</span>')
                if scanner["has_raw"]:
                    status_badges.append('<span class="badge badge-secondary">Raw Output</span>')
                
                scanners_html += f"""
                <div class="scanner-card">
                    <div class="scanner-header">
                        <h4>🔧 {scanner['name'].title()}</h4>
                        <span class="findings-count">{scanner['findings_count']} findings</span>
                    </div>
                    <div class="status-badges">
                        {' '.join(status_badges)}
                    </div>
                    <div class="scanner-actions">
                        <a href="scanners/{scanner['json_file']}" class="btn btn-primary">📋 View JSON Report</a>
                        <a href="scanners/scanner-report-{scanner['name']}.html" class="btn btn-secondary">📄 HTML View</a>
                    </div>
                </div>
                """
        
        severity_badges = self._generate_severity_badges(target_summary["severity_counts"])
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎯 Target Report - {target_summary['name']}</title>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="breadcrumb">
                <a href="../../../index.html">🏠 All Scans</a> / 
                <a href="../../index.html">📊 Scan</a> / 
                <span>{target_summary['name']}</span>
            </div>
            <h1>🎯 Target: {target_summary['name']}</h1>
            <div class="target-meta">
                <p><strong>Total Findings:</strong> {target_summary['total_findings']}</p>
                <p><strong>Scanners Run:</strong> {target_summary['scanners_count']}</p>
            </div>
            <div class="severity-summary">
                {severity_badges}
            </div>
        </header>
        
        <div class="summary-actions">
            <a href="findings.html" class="btn btn-primary">🔍 Browse Findings</a>
            <a href="combined_findings.json" class="btn btn-outline">📄 Combined Findings (JSON)</a>
        </div>
        
        <main class="main-content">
            <h2>🔧 Scanner Results</h2>
            <div class="scanners-grid">
                {scanners_html}
            </div>
        </main>
        
        <footer class="footer">
            <p><a href="../../index.html">← Back to Scan Overview</a></p>
        </footer>
    </div>
</body>
</html>"""
    
    def _generate_severity_badges(self, severity_counts: Dict[str, int]) -> str:
        """Generate HTML badges for severity counts."""
        badges = []
        severity_colors = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                color_class = severity_colors.get(severity, "secondary")
                badges.append(f'<span class="badge badge-{color_class}">{severity}: {count}</span>')
        
        return ' '.join(badges) if badges else '<span class="badge badge-success">No findings</span>'
    
    def _write_html_file(self, file_path: Path, content: str) -> None:
        """Write HTML content to file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the index pages."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        
        .header-stats {
            display: flex;
            gap: 30px;
            margin-top: 20px;
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-value {
            display: block;
            font-size: 2em;
            font-weight: bold;
            color: #fff;
        }
        
        .stat-label {
            display: block;
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .breadcrumb {
            margin-bottom: 15px;
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .breadcrumb a {
            color: white;
            text-decoration: none;
        }
        
        .breadcrumb a:hover {
            text-decoration: underline;
        }
        
        .scan-meta, .target-meta {
            margin-top: 15px;
            opacity: 0.9;
        }
        
        .scan-meta p, .target-meta p {
            margin-bottom: 5px;
        }
        
        .severity-summary, .severity-badges {
            margin-top: 15px;
        }
        
        .summary-actions {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        .main-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .main-content h2 {
            margin-bottom: 25px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .scans-grid, .targets-grid, .scanners-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
        }
        
        .scan-card, .target-card, .scanner-card {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            padding: 25px;
            transition: all 0.3s ease;
            border-left: 5px solid #667eea;
        }
        
        .scan-card:hover, .target-card:hover, .scanner-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .scan-header, .target-header, .scanner-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .scan-header h3, .target-header h4, .scanner-header h4 {
            margin: 0;
        }
        
        .scan-header h3 a, .target-header h4 a {
            color: #333;
            text-decoration: none;
        }
        
        .scan-header h3 a:hover, .target-header h4 a:hover {
            color: #667eea;
        }
        
        .timestamp, .findings-count {
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }
        
        .scan-stats {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .scan-stats .stat {
            text-align: left;
        }
        
        .scan-stats .stat-value {
            font-size: 1.5em;
            color: #667eea;
        }
        
        .scan-stats .stat-label {
            font-size: 0.85em;
            color: #666;
        }
        
        .scanners-used, .scanners-list {
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #666;
        }
        
        .description {
            margin-bottom: 15px;
            font-style: italic;
            color: #555;
        }
        
        .scan-actions, .target-actions, .scanner-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85em;
            font-weight: 500;
            transition: all 0.2s ease;
            border: none;
            cursor: pointer;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a6fd8;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        .btn-outline {
            background: transparent;
            color: #667eea;
            border: 1px solid #667eea;
        }
        
        .btn-outline:hover {
            background: #667eea;
            color: white;
        }
        
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 500;
            margin-right: 5px;
        }
        
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        .badge-success { background: #28a745; color: white; }
        .badge-secondary { background: #6c757d; color: white; }
        
        .no-scans, .no-targets, .no-scanners {
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .header-stats, .scan-stats {
                flex-direction: column;
                gap: 15px;
            }
            
            .scans-grid, .targets-grid, .scanners-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-actions {
                flex-direction: column;
            }
        }
        """


# Standalone function to generate index for existing reports
def generate_index_for_existing_reports(reports_dir: str = "reports") -> None:
    """
    Generate index files for existing reports with current structure.
    This function can be called to retrofit existing reports.
    """
    generator = ReportIndexGenerator(reports_dir)
    generator.generate_all_indexes()


if __name__ == "__main__":
    # Can be run standalone to generate indexes for existing reports
    import sys
    
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    generate_index_for_existing_reports(reports_dir)
    print(f"Generated index files for reports in: {reports_dir}")