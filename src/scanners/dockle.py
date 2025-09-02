"""
Dockle scanner implementation.

Dockle is a container image linter that helps build secure Docker images
by checking for security best practices and CIS benchmarks.
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class DockleScanner(BaseScanner):
    """Dockle container image linter implementation."""
    
    @property
    def name(self) -> str:
        return "dockle"
    
    @property
    def supported_targets(self) -> List[str]:
        return ["docker_image"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["dockle"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Dockle scan."""
        
        command = self._build_command(target)
        result = self._run_command(command)
        findings = self._parse_dockle_output(result.stdout, target)
        
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
        """Build Dockle command."""
        command = [
            "dockle",
            "--format", "json",
            
        ]
        
        command.extend(self.config.additional_args)
        command.append(target.path)
        
        return command
    
    def _parse_dockle_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Dockle JSON output."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            if "details" in data:
                for detail in data["details"]:
                    finding = Finding(
                        id=detail.get("code", "UNKNOWN"),
                        title=detail.get("title", "Container Security Issue"),
                        description=detail.get("description", "No description available"),
                        severity=self._map_dockle_level(detail.get("level", "INFO")),
                        scanner=self.name,
                        target=target.path,
                        location=target.path,
                        remediation=detail.get("description", "Follow Docker security best practices"),
                        metadata={
                            "code": detail.get("code"),
                            "level": detail.get("level"),
                            "alerts": detail.get("alerts", [])
                        }
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to parse Dockle output: {e}")
        
        return findings
    
    def _map_dockle_level(self, level: str) -> SeverityLevel:
        """Map Dockle severity levels."""
        mapping = {
            "FATAL": SeverityLevel.CRITICAL,
            "WARN": SeverityLevel.HIGH,
            "INFO": SeverityLevel.MEDIUM,
            "SKIP": SeverityLevel.LOW
        }
        return mapping.get(level.upper(), SeverityLevel.UNKNOWN)
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Dockle returns non-zero when issues are found."""
        return return_code in [0, 1]