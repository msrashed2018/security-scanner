"""
GitLeaks scanner implementation.

GitLeaks is a SAST tool for detecting and preventing secrets in git repos.
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class GitLeaksScanner(BaseScanner):
    """GitLeaks secrets scanner implementation."""
    
    @property
    def name(self) -> str:
        return "gitleaks"
    
    @property
    def supported_targets(self) -> List[str]:
        return ["git_repository", "filesystem"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["gitleaks"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute GitLeaks scan."""
        
        command = self._build_command(target)
        result = self._run_command(command)
        findings = self._parse_gitleaks_output(result.stdout, target)
        
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
        """Build GitLeaks command."""
        command = [
            "gitleaks",
            "detect",
            "--source", target.path,
            "--format", "json",
            "--no-git"
        ]
        
        command.extend(self.config.additional_args)
        return command
    
    def _parse_gitleaks_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse GitLeaks JSON output."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            for leak in data:
                finding = Finding(
                    id=f"GITLEAKS-{leak.get('RuleID', 'UNKNOWN')}",
                    title=f"Secret detected: {leak.get('Description', 'Unknown')}",
                    description=leak.get("Description", "Potential secret found"),
                    severity=SeverityLevel.HIGH,
                    scanner=self.name,
                    target=target.path,
                    location=f"{leak.get('File', 'unknown')}:{leak.get('StartLine', 'unknown')}",
                    remediation="Remove or secure the detected secret",
                    metadata={
                        "rule_id": leak.get("RuleID"),
                        "file": leak.get("File"),
                        "start_line": leak.get("StartLine"),
                        "end_line": leak.get("EndLine"),
                        "start_column": leak.get("StartColumn"),
                        "end_column": leak.get("EndColumn"),
                        "match": leak.get("Match"),
                        "secret": leak.get("Secret", "")[:20] + "***",  # Truncated
                        "date": leak.get("Date"),
                        "author": leak.get("Author"),
                        "email": leak.get("Email"),
                        "commit": leak.get("Commit"),
                        "entropy": leak.get("Entropy"),
                        "tags": leak.get("Tags", [])
                    }
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to parse GitLeaks output: {e}")
        
        return findings
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """GitLeaks returns non-zero when secrets are found."""
        return return_code in [0, 1]