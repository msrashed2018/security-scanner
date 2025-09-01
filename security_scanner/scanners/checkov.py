"""
Checkov scanner implementation.

Checkov is a static code analysis tool for Infrastructure as Code (IaC).
It scans Terraform, CloudFormation, Kubernetes, Dockerfile, and other IaC files.
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class CheckovScanner(BaseScanner):
    """Checkov Infrastructure as Code scanner implementation."""
    
    @property
    def name(self) -> str:
        return "checkov"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "terraform_code",
            "kubernetes_manifest", 
            "git_repository",
            "filesystem"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["checkov"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Checkov scan."""
        
        command = self._build_command(target)
        result = self._run_command(command)
        findings = self._parse_checkov_output(result.stdout, target)
        
        return ScanResult(
            scanner_name=self.name,
            target=target,
            status=None,
            start_time=None,
            findings=findings,
            raw_output=result.stdout,
            metadata={
                "command": " ".join(command),
                "return_code": result.returncode,
                "stderr": result.stderr
            }
        )
    
    def _build_command(self, target: ScanTarget) -> List[str]:
        """Build Checkov command."""
        command = [
            "checkov",
            "--output", "json",
            "--quiet"
        ]
        
        # Add target-specific flags
        if target.target_type.value == "terraform_code":
            command.extend(["--framework", "terraform"])
        elif target.target_type.value == "kubernetes_manifest":
            command.extend(["--framework", "kubernetes"])
        
        command.extend(self.config.additional_args)
        
        # Add directory or file
        command.extend(["-d", target.path])
        
        return command
    
    def _parse_checkov_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Checkov JSON output."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            # Parse failed checks
            failed_checks = data.get("results", {}).get("failed_checks", [])
            for check in failed_checks:
                finding = Finding(
                    id=check.get("check_id", "UNKNOWN"),
                    title=check.get("check_name", "Infrastructure Security Issue"),
                    description=check.get("description", "No description available"),
                    severity=self._map_checkov_severity(check.get("severity", "MEDIUM")),
                    scanner=self.name,
                    target=target.path,
                    location=f"{check.get('file_path', 'unknown')}:{check.get('file_line_range', ['unknown'])[0]}",
                    remediation=check.get("guideline", "Follow infrastructure security best practices"),
                    metadata={
                        "check_id": check.get("check_id"),
                        "check_class": check.get("check_class"),
                        "resource": check.get("resource"),
                        "file_path": check.get("file_path"),
                        "file_line_range": check.get("file_line_range"),
                        "code_block": check.get("code_block"),
                        "guideline": check.get("guideline")
                    }
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to parse Checkov output: {e}")
        
        return findings
    
    def _map_checkov_severity(self, severity: str) -> SeverityLevel:
        """Map Checkov severity levels."""
        mapping = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
            "INFO": SeverityLevel.INFO
        }
        return mapping.get(severity.upper(), SeverityLevel.MEDIUM)
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Checkov returns non-zero when issues are found."""
        return return_code in [0, 1]