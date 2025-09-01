"""
Conftest scanner implementation.

Conftest is a utility to help you write tests against structured configuration data.
"""

import json
from typing import List

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel


class ConftestScanner(BaseScanner):
    """Conftest policy scanner implementation."""
    
    @property
    def name(self) -> str:
        return "conftest"
    
    @property
    def supported_targets(self) -> List[str]:
        return ["kubernetes_manifest", "terraform_code", "git_repository", "filesystem"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["conftest"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Conftest scan."""
        command = [
            "conftest", "verify",
            "--output", "json",
            target.path
        ]
        command.extend(self.config.additional_args)
        
        result = self._run_command(command)
        findings = self._parse_conftest_output(result.stdout, target)
        
        return ScanResult(
            scanner_name=self.name,
            target=target,
            status=None,
            start_time=None,
            findings=findings,
            raw_output=result.stdout,
            metadata={"command": " ".join(command)}
        )
    
    def _parse_conftest_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Conftest JSON output."""
        findings = []
        try:
            data = self._parse_json_output(output)
            
            for result in data:
                for failure in result.get("failures", []):
                    finding = Finding(
                        id=f"CONFTEST-{hash(failure.get('msg', '')) % 10000:04d}",
                        title="Policy Violation",
                        description=failure.get("msg", "Policy violation detected"),
                        severity=SeverityLevel.MEDIUM,
                        scanner=self.name,
                        target=target.path,
                        location=result.get("filename", "unknown"),
                        remediation="Review and fix policy violations",
                        metadata=failure
                    )
                    findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse Conftest output: {e}")
        
        return findings
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Conftest returns non-zero when policy violations are found."""
        return return_code in [0, 1]