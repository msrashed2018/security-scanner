"""
KICS scanner implementation.

KICS (Keeping Infrastructure as Code Secure) finds security vulnerabilities,
compliance issues, and infrastructure misconfigurations.
"""

import json
from typing import List

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel


class KicsScanner(BaseScanner):
    """KICS Infrastructure as Code scanner implementation."""
    
    @property
    def name(self) -> str:
        return "kics"
    
    @property
    def supported_targets(self) -> List[str]:
        return ["terraform_code", "kubernetes_manifest", "git_repository", "filesystem"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["kics"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute KICS scan."""
        command = [
            "kics", "scan",
            "--path", target.path,
            "--output-format", "json",
            "--silent"
        ]
        command.extend(self.config.additional_args)
        
        result = self._run_command(command)
        findings = self._parse_kics_output(result.stdout, target)
        
        return ScanResult(
            scanner_name=self.name,
            target=target,
            status=None,
            start_time=None,
            findings=findings,
            raw_output=result.stdout,
            metadata={"command": " ".join(command)}
        )
    
    def _parse_kics_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse KICS JSON output."""
        findings = []
        try:
            data = self._parse_json_output(output)
            queries = data.get("queries", [])
            
            for query in queries:
                for file_result in query.get("files", []):
                    finding = Finding(
                        id=query.get("query_id", "UNKNOWN"),
                        title=query.get("query_name", "KICS Security Issue"),
                        description=query.get("description", "No description available"),
                        severity=self._map_kics_severity(query.get("severity", "MEDIUM")),
                        scanner=self.name,
                        target=target.path,
                        location=f"{file_result.get('file_name', 'unknown')}:{file_result.get('line', 'unknown')}",
                        remediation="Follow infrastructure security best practices",
                        metadata=query
                    )
                    findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse KICS output: {e}")
        
        return findings
    
    def _map_kics_severity(self, severity: str) -> SeverityLevel:
        """Map KICS severity levels."""
        mapping = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
            "INFO": SeverityLevel.INFO
        }
        return mapping.get(severity.upper(), SeverityLevel.MEDIUM)