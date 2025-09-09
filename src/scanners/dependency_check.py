"""
OWASP Dependency-Check scanner implementation.

OWASP Dependency-Check is a Software Composition Analysis (SCA) tool that attempts 
to detect publicly disclosed vulnerabilities contained within a project's dependencies.
It supports multiple programming languages and package managers.
"""

import json
import os
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel, ScanStatus
from ..core.config import ScannerConfig
from ..core.exceptions import ScanExecutionError


class DependencyCheckScanner(BaseScanner):
    """OWASP Dependency-Check scanner implementation."""
    
    @property
    def name(self) -> str:
        return "dependency-check"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "git_repository",
            "filesystem"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["dependency-check"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute OWASP Dependency-Check scan."""
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(temp_dir, "dependency-check-report.json")
            
            # Build command
            command = self._build_command(target, output_file)
            
            # Execute scan
            try:
                self.logger.info(f"Running Dependency-Check scan on {target.path}")
                result = self._run_command(command, timeout=self.config.timeout)
                
                # Parse results
                findings = self._parse_output(output_file, target)
                
                return ScanResult(
                    scanner_name=self.name,
                    target=target,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    metadata={
                        "command": " ".join(command),
                        "output_file": output_file,
                        "total_findings": len(findings)
                    }
                )
                
            except Exception as e:
                self.logger.error(f"Dependency-Check scan failed: {str(e)}")
                raise ScanExecutionError(self.name, str(e))
    
    def _build_command(self, target: ScanTarget, output_file: str) -> List[str]:
        """Build Dependency-Check command."""
        
        # Base command
        # Base command
        command = ["dependency-check"]

        # Get scanner-specific config
        project_name = self.config.get('project', target.name or "SecurityScan")
        scan_path = self.config.get('scan', target.path)
        output_format = self.config.get('format', 'JSON').upper()
        
        command.extend([
            "--project", project_name,
            "--scan", scan_path,
            "--format", output_format,
            "--out", os.path.dirname(output_file)
        ])
        
        if self.config.get('prettyPrint'):
            command.append("--prettyPrint")
        
        # Add severity threshold if configured
        if hasattr(self.config, 'severity_threshold') and self.config.severity_threshold:
            # Dependency-Check uses CVSS scores, map our severity to CVSS
            cvss_threshold = self._severity_to_cvss_threshold(self.config.severity_threshold)
            if cvss_threshold:
                command.extend(["--failOnCVSS", str(cvss_threshold)])
        
        # Add suppression file if configured
        if hasattr(self.config, 'suppression_file') and self.config.suppression_file:
            suppression_path = self.config.suppression_file
            if os.path.exists(suppression_path):
                command.extend(["--suppression", suppression_path])
        
        # Add database directory if configured
        if hasattr(self.config, 'database_directory') and self.config.database_directory:
            command.extend(["--data", self.config.database_directory])
        
        # Add update database flag if configured
        if hasattr(self.config, 'update_database') and self.config.update_database:
            command.append("--updateonly")
        
        # Add additional arguments from config
        if hasattr(self.config, 'additional_args') and self.config.additional_args:
            command.extend(self.config.additional_args)
        
        return command
    
    def _parse_output(self, output_file: str, target: ScanTarget) -> List[Finding]:
        """Parse Dependency-Check JSON output."""
        
        if not os.path.exists(output_file):
            self.logger.warning(f"Output file not found: {output_file}")
            return []
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            dependencies = data.get("dependencies", [])
            
            for dependency in dependencies:
                # Get dependency information
                file_name = dependency.get("fileName", "unknown")
                file_path = dependency.get("filePath", "")
                
                # Process vulnerabilities
                vulnerabilities = dependency.get("vulnerabilities", [])
                for vulnerability in vulnerabilities:
                    finding = self._create_finding_from_vulnerability(
                        vulnerability, dependency, target, file_path
                    )
                    if finding:
                        findings.append(finding)
            
            self.logger.info(f"Parsed {len(findings)} findings from Dependency-Check output")
            return findings
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON output: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing Dependency-Check output: {str(e)}")
            return []
    
    def _create_finding_from_vulnerability(
        self, 
        vulnerability: Dict[str, Any], 
        dependency: Dict[str, Any], 
        target: ScanTarget,
        file_path: str
    ) -> Optional[Finding]:
        """Create a Finding object from vulnerability data."""
        
        try:
            # Extract vulnerability information
            vuln_name = vulnerability.get("name", "UNKNOWN")
            description = vulnerability.get("description", "No description available")
            
            # Get CVSS score and severity
            cvss_v3 = vulnerability.get("cvssv3", {})
            cvss_v2 = vulnerability.get("cvssv2", {})
            
            # Prefer CVSS v3, fall back to v2
            cvss_score = None
            if cvss_v3 and cvss_v3.get("baseScore"):
                cvss_score = float(cvss_v3.get("baseScore"))
            elif cvss_v2 and cvss_v2.get("score"):
                cvss_score = float(cvss_v2.get("score"))
            
            # Map CVSS score to severity
            severity = self._cvss_to_severity(cvss_score) if cvss_score else SeverityLevel.UNKNOWN
            
            # Get component information
            component_name = dependency.get("fileName", "unknown")
            component_version = None
            
            # Try to extract version from evidence
            evidence = dependency.get("evidenceCollected", {})
            version_evidence = evidence.get("versionEvidence", [])
            if version_evidence:
                component_version = version_evidence[0].get("value", "unknown")
            
            # Build location string
            location = file_path if file_path else component_name
            if component_version:
                location += f" (version: {component_version})"
            
            # Extract references
            references = []
            refs = vulnerability.get("references", [])
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get("url") or ref.get("source")
                    if url:
                        references.append(url)
                elif isinstance(ref, str):
                    references.append(ref)
            
            # Build remediation advice
            remediation = self._build_remediation_advice(vulnerability, dependency)
            
            # Create finding
            finding = Finding(
                id=vuln_name,
                title=f"Vulnerable dependency: {component_name}",
                description=description,
                severity=severity,
                scanner=self.name,
                target=target.path,
                location=location,
                cve_id=vuln_name if vuln_name.startswith("CVE-") else None,
                cvss_score=cvss_score,
                references=references,
                remediation=remediation,
                metadata={
                    "component_name": component_name,
                    "component_version": component_version,
                    "file_path": file_path,
                    "vulnerability_source": vulnerability.get("source", ""),
                    "vulnerable_software": vulnerability.get("vulnerableSoftware", []),
                    "cvss_v3": cvss_v3,
                    "cvss_v2": cvss_v2,
                    "cwe": vulnerability.get("cwe", ""),
                    "dependency_sha1": dependency.get("sha1", ""),
                    "dependency_md5": dependency.get("md5", "")
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from vulnerability: {str(e)}")
            return None
    
    def _cvss_to_severity(self, cvss_score: float) -> SeverityLevel:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss_score >= 0.1:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _severity_to_cvss_threshold(self, severity: str) -> Optional[float]:
        """Convert severity level to CVSS threshold."""
        severity_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 0.1,
            "INFO": 0.0
        }
        return severity_map.get(severity.upper())
    
    def _build_remediation_advice(
        self, 
        vulnerability: Dict[str, Any], 
        dependency: Dict[str, Any]
    ) -> str:
        """Build remediation advice for the vulnerability."""
        
        advice_parts = []
        
        # Basic advice
        component_name = dependency.get("fileName", "the affected component")
        advice_parts.append(f"Update {component_name} to a version that fixes this vulnerability.")
        
        # Add specific version advice if available
        vulnerable_software = vulnerability.get("vulnerableSoftware", [])
        if vulnerable_software:
            advice_parts.append("Vulnerable versions include:")
            for software in vulnerable_software[:3]:  # Limit to first 3 entries
                advice_parts.append(f"  - {software}")
            if len(vulnerable_software) > 3:
                advice_parts.append(f"  - ... and {len(vulnerable_software) - 3} more")
        
        # Add reference to security advisory
        references = vulnerability.get("references", [])
        if references:
            advice_parts.append("For more information, see:")
            for ref in references[:2]:  # Limit to first 2 references
                if isinstance(ref, dict):
                    url = ref.get("url") or ref.get("source")
                    if url:
                        advice_parts.append(f"  - {url}")
                elif isinstance(ref, str):
                    advice_parts.append(f"  - {ref}")
        
        return "\n".join(advice_parts)
    
    def _detect_project_files(self, target_path: str) -> List[str]:
        """Detect project files that Dependency-Check can analyze."""
        
        project_files = []
        search_patterns = [
            # Java
            "pom.xml", "build.gradle", "gradle.properties", "ivy.xml",
            # JavaScript/Node.js
            "package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json",
            # Python
            "requirements.txt", "setup.py", "Pipfile", "Pipfile.lock", "pyproject.toml",
            # Ruby
            "Gemfile", "Gemfile.lock", "*.gemspec",
            # PHP
            "composer.json", "composer.lock",
            # .NET
            "packages.config", "*.csproj", "*.vbproj", "*.fsproj", "project.json",
            # Go
            "go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock",
            # Rust
            "Cargo.toml", "Cargo.lock",
            # Swift
            "Package.swift", "Package.resolved",
            # Scala
            "build.sbt"
        ]
        
        target_path_obj = Path(target_path)
        
        for pattern in search_patterns:
            if "*" in pattern:
                # Handle glob patterns
                matches = list(target_path_obj.rglob(pattern))
                project_files.extend([str(match) for match in matches])
            else:
                # Handle exact file names
                matches = list(target_path_obj.rglob(pattern))
                project_files.extend([str(match) for match in matches])
        
        return project_files