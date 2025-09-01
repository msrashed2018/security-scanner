"""
JSON output formatter for security scan reports.
"""

import json
from pathlib import Path

from .formatters import BaseFormatter
from ..core.models import ScanSummary
from ..core.config import OutputConfig


class JsonFormatter(BaseFormatter):
    """JSON output formatter."""
    
    @property
    def format_name(self) -> str:
        return "json"
    
    @property
    def file_extension(self) -> str:
        return "json"
    
    def generate_report(self, summary: ScanSummary, output_config: OutputConfig) -> str:
        """Generate JSON report."""
        
        # Create output directory
        output_dir = self._create_output_directory(output_config, summary.scan_id)
        
        # Generate main summary report
        summary_file = self._get_output_file_path(output_dir, summary.scan_id, "_summary")
        summary_content = self._generate_summary_json(summary, output_config)
        self._write_file(summary_file, summary_content)
        
        # Generate individual scanner reports if requested
        if output_config.include_raw:
            self._generate_individual_reports(summary, output_dir, output_config)
        
        return str(summary_file)
    
    def _generate_summary_json(self, summary: ScanSummary, output_config: OutputConfig) -> str:
        """Generate the main summary JSON."""
        
        # Convert summary to dictionary
        summary_dict = summary.to_dict()
        
        # Add metadata
        summary_dict["metadata"].update({
            "report_format": "json",
            "generator": "security-scanner",
            "version": "1.0.0"
        })
        
        # Remove raw output if not requested
        if not output_config.include_raw:
            for result in summary_dict.get("results", []):
                result.pop("raw_output", None)
        
        return json.dumps(summary_dict, indent=2, default=str)
    
    def _generate_individual_reports(self, summary: ScanSummary, output_dir: Path, output_config: OutputConfig) -> None:
        """Generate individual JSON reports for each scanner/target combination."""
        
        # Group results by scanner and target
        grouped_results = {}
        
        for result in summary.results:
            scanner_name = result.scanner_name
            target_name = result.target.name or "unknown"
            
            key = f"{scanner_name}_{target_name}"
            if key not in grouped_results:
                grouped_results[key] = []
            grouped_results[key].append(result)
        
        # Generate individual reports
        for key, results in grouped_results.items():
            if len(results) == 1:
                result = results[0]
                individual_file = output_dir / f"{key}.json"
                individual_content = json.dumps(result.to_dict(), indent=2, default=str)
                self._write_file(individual_file, individual_content)
        
        # Generate findings-only report
        findings_file = output_dir / f"{summary.scan_id}_findings.json"
        findings_data = {
            "scan_id": summary.scan_id,
            "scan_time": summary.start_time.isoformat(),
            "total_findings": summary.total_findings,
            "findings_by_severity": summary.overall_finding_counts,
            "findings": []
        }
        
        for result in summary.results:
            for finding in result.findings:
                finding_dict = finding.to_dict()
                finding_dict["scanner"] = result.scanner_name
                findings_data["findings"].append(finding_dict)
        
        findings_content = json.dumps(findings_data, indent=2, default=str)
        self._write_file(findings_file, findings_content)