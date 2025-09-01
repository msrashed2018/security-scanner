"""
Grype scanner implementation.

Grype is a vulnerability scanner for container images and filesystems.
It's designed to be fast and accurate, often used alongside Syft for SBOM generation.
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class GrypeScanner(BaseScanner):
    """Grype vulnerability scanner implementation."""
    
    @property
    def name(self) -> str:
        return "grype"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "docker_image",
            "git_repository",
            "filesystem"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["grype"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Grype scan."""
        
        # Build command
        command = self._build_command(target)
        
        # Execute scan
        result = self._run_command(command)
        
        # Parse results
        findings = self._parse_grype_output(result.stdout, target)
        
        return ScanResult(
            scanner_name=self.name,
            target=target,
            status=None,  # Will be set by base class
            start_time=None,  # Will be set by base class
            findings=findings,
            raw_output=result.stdout,
            metadata={
                "command": " ".join(command),
                "return_code": result.returncode,
                "stderr": result.stderr
            }
        )
    
    def _build_command(self, target: ScanTarget) -> List[str]:
        """Build Grype command."""
        command = [
            "grype",
            "--output", "json",
            "--quiet"
        ]
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        # Add target
        if target.target_type.value == "docker_image":
            command.append(target.path)
        else:
            # For filesystem and git repositories
            command.extend(["dir:" + target.path])
        
        return command
    
    def _get_severity_levels(self, threshold: str) -> List[str]:
        """Get severity levels to include based on threshold."""
        severity_order = ["negligible", "low", "medium", "high", "critical"]
        threshold_map = {
            "INFO": "negligible",
            "LOW": "low", 
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical"
        }
        
        threshold_level = threshold_map.get(threshold, "medium")
        threshold_index = severity_order.index(threshold_level)
        return severity_order[threshold_index:]
    
    def _parse_grype_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Grype JSON output into Finding objects."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            if "matches" in data:
                for match in data["matches"]:
                    finding = self._create_finding_from_match(match, target)
                    if finding:
                        findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Failed to parse Grype output: {e}")
        
        return findings
    
    def _create_finding_from_match(self, match: Dict[str, Any], target: ScanTarget) -> Finding:
        """Create a Finding object from a Grype match."""
        
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        
        # Extract basic information
        vuln_id = vulnerability.get("id", "UNKNOWN")
        severity = self._normalize_grype_severity(vulnerability.get("severity", "Unknown"))
        
        # Build location string
        location_parts = []
        if artifact.get("name"):
            location_parts.append(artifact["name"])
        if artifact.get("version"):
            location_parts.append(f"v{artifact['version']}")
        if artifact.get("locations"):
            # Get first location
            first_location = artifact["locations"][0] if artifact["locations"] else {}
            if first_location.get("path"):
                location_parts.append(first_location["path"])
        
        location = ":".join(location_parts) if location_parts else "unknown"
        
        # Extract CVSS score
        cvss_score = None
        if vulnerability.get("cvss"):
            for cvss_data in vulnerability["cvss"]:
                if cvss_data.get("metrics", {}).get("baseScore"):
                    cvss_score = float(cvss_data["metrics"]["baseScore"])
                    break
        
        # Build remediation text
        remediation = self._build_remediation_text(match)
        
        # Extract references
        references = []
        if vulnerability.get("urls"):
            references.extend(vulnerability["urls"])
        if vulnerability.get("dataSource"):
            references.append(vulnerability["dataSource"])
        
        finding = Finding(
            id=vuln_id,
            title=vulnerability.get("description", vuln_id),
            description=vulnerability.get("description", "No description available"),
            severity=severity,
            scanner=self.name,
            target=target.path,
            location=location,
            cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
            cvss_score=cvss_score,
            references=references,
            remediation=remediation,
            metadata={
                "package_name": artifact.get("name"),
                "package_version": artifact.get("version"),
                "package_type": artifact.get("type"),
                "package_language": artifact.get("language"),
                "package_locations": artifact.get("locations", []),
                "vulnerability_namespace": vulnerability.get("namespace"),
                "vulnerability_severity": vulnerability.get("severity"),
                "vulnerability_fix_state": vulnerability.get("fix", {}).get("state"),
                "vulnerability_fix_versions": vulnerability.get("fix", {}).get("versions", []),
                "match_details": match.get("matchDetails", []),
                "related_vulnerabilities": match.get("relatedVulnerabilities", [])
            }
        )
        
        return finding
    
    def _normalize_grype_severity(self, severity: str) -> SeverityLevel:
        """Normalize Grype severity to SeverityLevel enum."""
        severity_map = {
            "negligible": SeverityLevel.INFO,
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL,
            "unknown": SeverityLevel.UNKNOWN
        }
        
        return severity_map.get(severity.lower(), SeverityLevel.UNKNOWN)
    
    def _build_remediation_text(self, match: Dict[str, Any]) -> str:
        """Build remediation text for vulnerability."""
        remediation_parts = []
        
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        
        # Check for fix information
        fix_info = vulnerability.get("fix", {})
        if fix_info.get("state") == "fixed" and fix_info.get("versions"):
            package_name = artifact.get("name", "package")
            fixed_versions = fix_info["versions"]
            if fixed_versions:
                remediation_parts.append(
                    f"Update {package_name} to version {fixed_versions[0]} or later"
                )
        elif fix_info.get("state") == "not-fixed":
            remediation_parts.append("No fix available yet")
        elif fix_info.get("state") == "wont-fix":
            remediation_parts.append("Vendor will not fix this vulnerability")
        
        # Add general advice
        if not remediation_parts:
            remediation_parts.append("Check for updated versions of the affected package")
        
        # Add reference to vulnerability database
        if vulnerability.get("dataSource"):
            remediation_parts.append(f"See: {vulnerability['dataSource']}")
        
        return ". ".join(remediation_parts)
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Grype returns non-zero when vulnerabilities are found."""
        # Grype returns 0 for no vulnerabilities, 1 for vulnerabilities found, >1 for errors
        return return_code in [0, 1]