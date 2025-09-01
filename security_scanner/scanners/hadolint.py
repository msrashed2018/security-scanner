"""
Hadolint scanner implementation.

Hadolint is a Dockerfile linter that helps you build best practice Docker images.
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class HadolintScanner(BaseScanner):
    """Hadolint Dockerfile linter implementation."""
    
    @property
    def name(self) -> str:
        return "hadolint"
    
    @property
    def supported_targets(self) -> List[str]:
        return ["git_repository", "filesystem"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["hadolint"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Hadolint scan."""
        
        # Find Dockerfiles in the target
        dockerfiles = self._find_dockerfiles(target.path)
        findings = []
        
        for dockerfile in dockerfiles:
            command = ["hadolint", "--format", "json", dockerfile]
            command.extend(self.config.additional_args)
            
            try:
                result = self._run_command(command)
                findings.extend(self._parse_hadolint_output(result.stdout, target, dockerfile))
            except Exception as e:
                self.logger.warning(f"Failed to scan {dockerfile}: {e}")
        
        return ScanResult(
            scanner_name=self.name,
            target=target,
            status=None,
            start_time=None,
            findings=findings,
            raw_output="",
            metadata={"dockerfiles_scanned": len(dockerfiles)}
        )
    
    def _find_dockerfiles(self, path: str) -> List[str]:
        """Find Dockerfile in the given path."""
        import os
        dockerfiles = []
        
        if os.path.isfile(path) and ("dockerfile" in path.lower() or path.endswith("Dockerfile")):
            dockerfiles.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.lower() in ["dockerfile", "dockerfile.dev", "dockerfile.prod"] or file.startswith("Dockerfile"):
                        dockerfiles.append(os.path.join(root, file))
        
        return dockerfiles
    
    def _parse_hadolint_output(self, output: str, target: ScanTarget, dockerfile: str) -> List[Finding]:
        """Parse Hadolint JSON output."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            for issue in data:
                finding = Finding(
                    id=issue.get("code", "UNKNOWN"),
                    title=f"Dockerfile issue: {issue.get('code', 'Unknown')}",
                    description=issue.get("message", "No description available"),
                    severity=self._map_hadolint_level(issue.get("level", "info")),
                    scanner=self.name,
                    target=target.path,
                    location=f"{dockerfile}:{issue.get('line', 'unknown')}",
                    remediation="Follow Dockerfile best practices",
                    metadata={
                        "code": issue.get("code"),
                        "level": issue.get("level"),
                        "line": issue.get("line"),
                        "column": issue.get("column"),
                        "file": dockerfile
                    }
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to parse Hadolint output: {e}")
        
        return findings
    
    def _map_hadolint_level(self, level: str) -> SeverityLevel:
        """Map Hadolint severity levels."""
        mapping = {
            "error": SeverityLevel.HIGH,
            "warning": SeverityLevel.MEDIUM,
            "info": SeverityLevel.LOW,
            "style": SeverityLevel.INFO
        }
        return mapping.get(level.lower(), SeverityLevel.UNKNOWN)