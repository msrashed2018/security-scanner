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

from ..core.template_loader import template_loader

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
                    "has_report": (scanner_file.parent / f"scanner-report-{scanner_name}.html").exists(),
                    "has_findings": True,
                    "has_raw": True,
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
                        <a href="{scan['scan_dir']}/findings-browser.html" class="btn btn-primary">🔍 Browse Findings</a>
                    </div>
                </div>
                """
        
        context = {
            'css_styles': self._get_css_styles(),
            'total_scans': len(scan_summaries),
            'total_targets': sum(s['targets_count'] for s in scan_summaries),
            'total_findings': sum(s['total_findings'] for s in scan_summaries),
            'scans_html': scans_html,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return template_loader.render('index_main.html', context)
    
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
        
        context = {
            'css_styles': self._get_css_styles(),
            'scan_id': scan_summary['scan_id'],
            'timestamp': scan_summary['timestamp'],
            'targets_count': scan_summary['targets_count'],
            'total_findings': scan_summary['total_findings'],
            'scanners_used': ', '.join(scan_summary['scanners_used']) if scan_summary['scanners_used'] else 'None',
            'targets_html': targets_html
        }
        
        return template_loader.render('index_scan.html', context)
    
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
        
        context = {
            'css_styles': self._get_css_styles(),
            'target_name': target_summary['name'],
            'total_findings': target_summary['total_findings'],
            'scanners_count': target_summary['scanners_count'],
            'severity_badges': self._generate_severity_badges(target_summary["severity_counts"]),
            'scanners_html': scanners_html
        }
        
        return template_loader.render('index_target.html', context)
    
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
        return template_loader.load_template('index.css')


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
    
    reports_dir = sys.argv if len(sys.argv) > 1 else "reports"
    generate_index_for_existing_reports(reports_dir)
    print(f"Generated index files for reports in: {reports_dir}")