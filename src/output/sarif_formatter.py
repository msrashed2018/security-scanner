"""
SARIF (Static Analysis Results Interchange Format) output formatter.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from .formatters import BaseFormatter
from ..core.models import ScanSummary, ScanResult, Finding, SeverityLevel
from ..core.config import OutputConfig


class SarifFormatter(BaseFormatter):
    """SARIF output formatter."""
    
    @property
    def format_name(self) -> str:
        return "sarif"
    
    @property
    def file_extension(self) -> str:
        return "sarif"
    
    def generate_report(self, summary: ScanSummary, output_config: OutputConfig) -> str:
        """Generate SARIF report."""
        
        # Use hierarchical structure: place SARIF files in raw-data subdirectory
        scan_dir = Path(output_config.base_dir) / summary.scan_id
        output_dir = scan_dir / "raw-data"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate SARIF report
        sarif_file = output_dir / f"{summary.scan_id}.sarif"
        sarif_content = self._generate_sarif_json(summary)
        self._write_file(sarif_file, sarif_content)
        
        return str(sarif_file)
    
    def _generate_sarif_json(self, summary: ScanSummary) -> str:
        """Generate SARIF JSON content."""
        
        # Create SARIF document structure
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": []
        }
        
        # Group results by scanner
        scanner_results = {}
        for result in summary.results:
            scanner_name = result.scanner_name
            if scanner_name not in scanner_results:
                scanner_results[scanner_name] = []
            scanner_results[scanner_name].append(result)
        
        # Create a run for each scanner
        for scanner_name, results in scanner_results.items():
            run = self._create_sarif_run(scanner_name, results, summary)
            sarif_doc["runs"].append(run)
        
        return json.dumps(sarif_doc, indent=2, default=str)
    
    def _create_sarif_run(self, scanner_name: str, results: List[ScanResult], summary: ScanSummary) -> Dict[str, Any]:
        """Create a SARIF run for a specific scanner."""
        
        # Collect all findings from this scanner
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        # Create tool information
        tool = {
            "driver": {
                "name": scanner_name,
                "version": "latest",
                "informationUri": self._get_scanner_info_uri(scanner_name),
                "rules": self._create_sarif_rules(all_findings)
            }
        }
        
        # Create results
        sarif_results = []
        for result in results:
            for finding in result.findings:
                sarif_result = self._create_sarif_result(finding, result)
                sarif_results.append(sarif_result)
        
        # Create run
        run = {
            "tool": tool,
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": summary.start_time.isoformat() + "Z",
                "endTimeUtc": summary.end_time.isoformat() + "Z" if summary.end_time else None,
                "workingDirectory": {
                    "uri": "file:///"
                }
            }],
            "artifacts": self._create_sarif_artifacts(results)
        }
        
        return run
    
    def _create_sarif_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create SARIF rules from findings."""
        rules = {}
        
        for finding in findings:
            rule_id = finding.id
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                    "properties": {
                        "security-severity": self._severity_to_security_score(finding.severity)
                    }
                }
                
                if finding.remediation:
                    rules[rule_id]["help"] = {
                        "text": finding.remediation
                    }
        
        return list(rules.values())
    
    def _create_sarif_result(self, finding: Finding, scan_result: ScanResult) -> Dict[str, Any]:
        """Create a SARIF result from a finding."""
        
        result = {
            "ruleId": finding.id,
            "ruleIndex": 0,  # Would need to be calculated properly
            "level": self._severity_to_sarif_level(finding.severity),
            "message": {
                "text": finding.description
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": self._normalize_uri(scan_result.target.path)
                    }
                }
            }]
        }
        
        # Add line information if available
        if finding.location and ":" in finding.location:
            parts = finding.location.split(":")
            if len(parts) >= 2 and parts[1].isdigit():
                result["locations"][0]["physicalLocation"]["region"] = {
                    "startLine": int(parts[1])
                }
        
        # Add properties
        properties = {
            "scanner": finding.scanner,
            "target": finding.target
        }
        
        if finding.cve_id:
            properties["cve"] = finding.cve_id
        
        if finding.cvss_score:
            properties["cvss_score"] = finding.cvss_score
        
        if finding.metadata:
            properties.update(finding.metadata)
        
        result["properties"] = properties
        
        return result
    
    def _create_sarif_artifacts(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Create SARIF artifacts from scan results."""
        artifacts = {}
        
        for result in results:
            uri = self._normalize_uri(result.target.path)
            if uri not in artifacts:
                artifacts[uri] = {
                    "location": {
                        "uri": uri
                    },
                    "description": {
                        "text": f"Scan target: {result.target.name}"
                    }
                }
        
        return list(artifacts.values())
    
    def _severity_to_sarif_level(self, severity: SeverityLevel) -> str:
        """Convert severity level to SARIF level."""
        mapping = {
            SeverityLevel.CRITICAL: "error",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "note",
            SeverityLevel.INFO: "note",
            SeverityLevel.UNKNOWN: "note"
        }
        return mapping.get(severity, "note")
    
    def _severity_to_security_score(self, severity: SeverityLevel) -> str:
        """Convert severity level to security score."""
        mapping = {
            SeverityLevel.CRITICAL: "9.0",
            SeverityLevel.HIGH: "7.0",
            SeverityLevel.MEDIUM: "5.0",
            SeverityLevel.LOW: "3.0",
            SeverityLevel.INFO: "1.0",
            SeverityLevel.UNKNOWN: "0.0"
        }
        return mapping.get(severity, "0.0")
    
    def _normalize_uri(self, path: str) -> str:
        """Normalize path to URI format."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        elif path.startswith("/"):
            return f"file://{path}"
        else:
            return f"file:///{path}"
    
    def _get_scanner_info_uri(self, scanner_name: str) -> str:
        """Get information URI for a scanner."""
        uris = {
            "trivy": "https://github.com/aquasecurity/trivy",
            "grype": "https://github.com/anchore/grype",
            "syft": "https://github.com/anchore/syft",
            "dockle": "https://github.com/goodwithtech/dockle",
            "hadolint": "https://github.com/hadolint/hadolint",
            "checkov": "https://github.com/bridgecrewio/checkov",
            "kics": "https://github.com/Checkmarx/kics",
            "conftest": "https://github.com/open-policy-agent/conftest",
            "trufflehog": "https://github.com/trufflesecurity/trufflehog",
            "gitleaks": "https://github.com/zricethezav/gitleaks"
        }
        return uris.get(scanner_name, "https://github.com/security-scanner")