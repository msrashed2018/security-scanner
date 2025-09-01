"""
Trivy scanner implementation.

Trivy is a comprehensive security scanner for containers, filesystems, and Git repositories.
It can detect vulnerabilities, misconfigurations, secrets, and licenses.
"""

import json
from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class TrivyScanner(BaseScanner):
    """Trivy security scanner implementation."""
    
    @property
    def name(self) -> str:
        return "trivy"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "docker_image",
            "git_repository", 
            "filesystem",
            "kubernetes_manifest",
            "terraform_code"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["trivy"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Trivy scan."""
        
        # Build command based on target type
        if target.target_type.value == "docker_image":
            command = self._build_image_command(target)
        elif target.target_type.value in ["git_repository", "filesystem"]:
            command = self._build_filesystem_command(target)
        elif target.target_type.value in ["kubernetes_manifest", "terraform_code"]:
            command = self._build_config_command(target)
        else:
            raise ValueError(f"Unsupported target type: {target.target_type.value}")
        
        # Execute scan
        result = self._run_command(command)
        
        # Parse results
        findings = self._parse_trivy_output(result.stdout, target)
        
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
    
    def _build_image_command(self, target: ScanTarget) -> List[str]:
        """Build Trivy command for Docker image scanning."""
        command = [
            "trivy",
            "image",
            "--format", "json",
            "--timeout", f"{self.config.timeout}s"
        ]
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        # Add scanners
        scanners = ["vuln", "misconfig", "secret", "license"]
        command.extend(["--scanners", ",".join(scanners)])
        
        # Add severity filter
        if self.config.severity_threshold != "INFO":
            severity_levels = self._get_severity_levels(self.config.severity_threshold)
            command.extend(["--severity", ",".join(severity_levels)])
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        # Add target image
        command.append(target.path)
        
        return command
    
    def _build_filesystem_command(self, target: ScanTarget) -> List[str]:
        """Build Trivy command for filesystem scanning."""
        command = [
            "trivy",
            "fs",
            "--format", "json",
            "--timeout", f"{self.config.timeout}s"
        ]
        
        # Add scanners
        scanners = ["vuln", "misconfig", "secret", "license"]
        command.extend(["--scanners", ",".join(scanners)])
        
        # Add severity filter
        if self.config.severity_threshold != "INFO":
            severity_levels = self._get_severity_levels(self.config.severity_threshold)
            command.extend(["--severity", ",".join(severity_levels)])
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        # Add target path
        command.append(target.path)
        
        return command
    
    def _build_config_command(self, target: ScanTarget) -> List[str]:
        """Build Trivy command for configuration scanning."""
        command = [
            "trivy",
            "config",
            "--format", "json",
            "--timeout", f"{self.config.timeout}s"
        ]
        
        # Add severity filter
        if self.config.severity_threshold != "INFO":
            severity_levels = self._get_severity_levels(self.config.severity_threshold)
            command.extend(["--severity", ",".join(severity_levels)])
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        # Add target path
        command.append(target.path)
        
        return command
    
    def _get_severity_levels(self, threshold: str) -> List[str]:
        """Get severity levels to include based on threshold."""
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_index = severity_order.index(threshold)
        return severity_order[threshold_index:]
    
    def _parse_trivy_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Trivy JSON output into Finding objects."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            if "Results" in data:
                for result in data["Results"]:
                    # Parse vulnerabilities
                    if "Vulnerabilities" in result:
                        findings.extend(self._parse_vulnerabilities(
                            result["Vulnerabilities"], 
                            result.get("Target", target.path),
                            target
                        ))
                    
                    # Parse misconfigurations
                    if "Misconfigurations" in result:
                        findings.extend(self._parse_misconfigurations(
                            result["Misconfigurations"],
                            result.get("Target", target.path),
                            target
                        ))
                    
                    # Parse secrets
                    if "Secrets" in result:
                        findings.extend(self._parse_secrets(
                            result["Secrets"],
                            result.get("Target", target.path),
                            target
                        ))
                    
                    # Parse licenses
                    if "Licenses" in result:
                        findings.extend(self._parse_licenses(
                            result["Licenses"],
                            result.get("Target", target.path),
                            target
                        ))
            
        except Exception as e:
            self.logger.error(f"Failed to parse Trivy output: {e}")
        
        return findings
    
    def _parse_vulnerabilities(self, vulnerabilities: List[Dict], target_name: str, target: ScanTarget) -> List[Finding]:
        """Parse vulnerability findings."""
        findings = []
        
        for vuln in vulnerabilities:
            finding = Finding(
                id=vuln.get("VulnerabilityID", "UNKNOWN"),
                title=vuln.get("Title", vuln.get("VulnerabilityID", "Unknown Vulnerability")),
                description=vuln.get("Description", "No description available"),
                severity=self._normalize_severity(vuln.get("Severity", "UNKNOWN")),
                scanner=self.name,
                target=target.path,
                location=f"{target_name}:{vuln.get('PkgName', 'unknown')}",
                cve_id=vuln.get("VulnerabilityID") if vuln.get("VulnerabilityID", "").startswith("CVE-") else None,
                cvss_score=self._extract_cvss_score(vuln),
                references=vuln.get("References", []),
                remediation=self._build_remediation_text(vuln),
                metadata={
                    "package_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "pkg_path": vuln.get("PkgPath"),
                    "layer": vuln.get("Layer", {}).get("DiffID") if vuln.get("Layer") else None,
                    "data_source": vuln.get("DataSource"),
                    "primary_url": vuln.get("PrimaryURL")
                }
            )
            findings.append(finding)
        
        return findings
    
    def _parse_misconfigurations(self, misconfigs: List[Dict], target_name: str, target: ScanTarget) -> List[Finding]:
        """Parse misconfiguration findings."""
        findings = []
        
        for misconfig in misconfigs:
            finding = Finding(
                id=misconfig.get("ID", "UNKNOWN"),
                title=misconfig.get("Title", misconfig.get("ID", "Unknown Misconfiguration")),
                description=misconfig.get("Description", "No description available"),
                severity=self._normalize_severity(misconfig.get("Severity", "UNKNOWN")),
                scanner=self.name,
                target=target.path,
                location=f"{target_name}:{misconfig.get('CauseMetadata', {}).get('StartLine', 'unknown')}",
                references=misconfig.get("References", []),
                remediation=misconfig.get("Resolution", "No remediation available"),
                metadata={
                    "type": misconfig.get("Type"),
                    "check_id": misconfig.get("ID"),
                    "namespace": misconfig.get("Namespace"),
                    "query": misconfig.get("Query"),
                    "message": misconfig.get("Message"),
                    "cause_metadata": misconfig.get("CauseMetadata", {})
                }
            )
            findings.append(finding)
        
        return findings
    
    def _parse_secrets(self, secrets: List[Dict], target_name: str, target: ScanTarget) -> List[Finding]:
        """Parse secret findings."""
        findings = []
        
        for secret in secrets:
            finding = Finding(
                id=f"SECRET-{secret.get('RuleID', 'UNKNOWN')}",
                title=f"Secret detected: {secret.get('Title', secret.get('RuleID', 'Unknown Secret'))}",
                description=f"Potential secret found: {secret.get('Match', 'No details available')}",
                severity=SeverityLevel.HIGH,  # Secrets are always high severity
                scanner=self.name,
                target=target.path,
                location=f"{target_name}:{secret.get('StartLine', 'unknown')}",
                remediation="Remove or secure the detected secret",
                metadata={
                    "rule_id": secret.get("RuleID"),
                    "category": secret.get("Category"),
                    "match": secret.get("Match"),
                    "start_line": secret.get("StartLine"),
                    "end_line": secret.get("EndLine"),
                    "code": secret.get("Code", {})
                }
            )
            findings.append(finding)
        
        return findings
    
    def _parse_licenses(self, licenses: List[Dict], target_name: str, target: ScanTarget) -> List[Finding]:
        """Parse license findings."""
        findings = []
        
        for license_info in licenses:
            # Only report problematic licenses
            severity = self._get_license_severity(license_info.get("Name", ""))
            if severity == SeverityLevel.INFO:
                continue
            
            finding = Finding(
                id=f"LICENSE-{license_info.get('Name', 'UNKNOWN')}",
                title=f"License issue: {license_info.get('Name', 'Unknown License')}",
                description=f"Potentially problematic license detected",
                severity=severity,
                scanner=self.name,
                target=target.path,
                location=f"{target_name}:{license_info.get('PkgName', 'unknown')}",
                remediation="Review license compatibility with your project",
                metadata={
                    "license_name": license_info.get("Name"),
                    "package_name": license_info.get("PkgName"),
                    "file_path": license_info.get("FilePath"),
                    "confidence": license_info.get("Confidence")
                }
            )
            findings.append(finding)
        
        return findings
    
    def _extract_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability data."""
        cvss = vuln.get("CVSS", {})
        
        # Try different CVSS versions
        for version in ["nvd", "redhat", "ghsa"]:
            if version in cvss and "V3Score" in cvss[version]:
                return float(cvss[version]["V3Score"])
            elif version in cvss and "V2Score" in cvss[version]:
                return float(cvss[version]["V2Score"])
        
        return None
    
    def _build_remediation_text(self, vuln: Dict) -> str:
        """Build remediation text for vulnerability."""
        remediation_parts = []
        
        if vuln.get("FixedVersion"):
            remediation_parts.append(f"Update {vuln.get('PkgName')} to version {vuln.get('FixedVersion')}")
        
        if vuln.get("PrimaryURL"):
            remediation_parts.append(f"See: {vuln.get('PrimaryURL')}")
        
        return ". ".join(remediation_parts) if remediation_parts else "No specific remediation available"
    
    def _get_license_severity(self, license_name: str) -> SeverityLevel:
        """Determine severity level for a license."""
        license_name = license_name.lower()
        
        # High risk licenses
        high_risk = ["gpl", "agpl", "copyleft"]
        if any(risk in license_name for risk in high_risk):
            return SeverityLevel.HIGH
        
        # Medium risk licenses
        medium_risk = ["lgpl", "mpl", "cpl", "epl"]
        if any(risk in license_name for risk in medium_risk):
            return SeverityLevel.MEDIUM
        
        # Low risk licenses
        low_risk = ["unknown", "proprietary"]
        if any(risk in license_name for risk in low_risk):
            return SeverityLevel.LOW
        
        return SeverityLevel.INFO
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Trivy returns non-zero when vulnerabilities are found."""
        # Trivy returns 0 for success, 1 for vulnerabilities found, >1 for errors
        return return_code in [0, 1]