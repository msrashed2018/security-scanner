"""
Syft scanner implementation.

Syft generates Software Bill of Materials (SBOM) for container images and filesystems.
It catalogs packages and dependencies in various formats (SPDX, CycloneDX, etc.).
"""

import json
from typing import List, Dict, Any

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class SyftScanner(BaseScanner):
    """Syft SBOM generator implementation."""
    
    @property
    def name(self) -> str:
        return "syft"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "docker_image",
            "git_repository",
            "filesystem"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["syft"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Syft scan to generate SBOM."""
        
        # Build command
        command = self._build_command(target)
        
        # Execute scan
        result = self._run_command(command)
        
        # Parse results - Syft generates SBOM data, not vulnerabilities
        # We'll create informational findings about the packages discovered
        findings = self._parse_syft_output(result.stdout, target)
        
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
                "stderr": result.stderr,
                "sbom_format": "json"
            }
        )
    
    def _build_command(self, target: ScanTarget) -> List[str]:
        """Build Syft command."""
        command = [
            "syft",
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
            command.append(f"dir:{target.path}")
        
        return command
    
    def _parse_syft_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Syft JSON output into Finding objects."""
        findings = []
        
        try:
            data = self._parse_json_output(output)
            
            # Extract artifacts (packages)
            artifacts = data.get("artifacts", [])
            
            # Create summary findings
            findings.extend(self._create_summary_findings(artifacts, target, data))
            
            # Optionally create individual package findings for important packages
            findings.extend(self._create_package_findings(artifacts, target))
            
        except Exception as e:
            self.logger.error(f"Failed to parse Syft output: {e}")
        
        return findings
    
    def _create_summary_findings(self, artifacts: List[Dict], target: ScanTarget, data: Dict) -> List[Finding]:
        """Create summary findings about the SBOM."""
        findings = []
        
        # Overall SBOM summary
        total_packages = len(artifacts)
        package_types = {}
        languages = {}
        
        for artifact in artifacts:
            pkg_type = artifact.get("type", "unknown")
            package_types[pkg_type] = package_types.get(pkg_type, 0) + 1
            
            language = artifact.get("language", "unknown")
            if language != "unknown":
                languages[language] = languages.get(language, 0) + 1
        
        # Create summary finding
        summary_description = f"Software Bill of Materials (SBOM) generated with {total_packages} packages"
        if package_types:
            type_summary = ", ".join([f"{count} {pkg_type}" for pkg_type, count in package_types.items()])
            summary_description += f". Package types: {type_summary}"
        
        summary_finding = Finding(
            id="SBOM-SUMMARY",
            title="Software Bill of Materials Generated",
            description=summary_description,
            severity=SeverityLevel.INFO,
            scanner=self.name,
            target=target.path,
            location=target.path,
            metadata={
                "total_packages": total_packages,
                "package_types": package_types,
                "languages": languages,
                "sbom_schema": data.get("schema", {}),
                "source": data.get("source", {}),
                "distro": data.get("distro", {})
            }
        )
        findings.append(summary_finding)
        
        # Create findings for potential security concerns
        findings.extend(self._analyze_sbom_for_concerns(artifacts, target))
        
        return findings
    
    def _create_package_findings(self, artifacts: List[Dict], target: ScanTarget) -> List[Finding]:
        """Create individual findings for important packages."""
        findings = []
        
        # Only create findings for packages that might be of security interest
        important_packages = self._identify_important_packages(artifacts)
        
        for package in important_packages:
            finding = Finding(
                id=f"PACKAGE-{package.get('name', 'unknown')}",
                title=f"Package: {package.get('name', 'unknown')}",
                description=f"Package {package.get('name')} version {package.get('version')} detected",
                severity=SeverityLevel.INFO,
                scanner=self.name,
                target=target.path,
                location=self._get_package_location(package),
                metadata={
                    "package_name": package.get("name"),
                    "package_version": package.get("version"),
                    "package_type": package.get("type"),
                    "package_language": package.get("language"),
                    "package_licenses": package.get("licenses", []),
                    "package_locations": package.get("locations", []),
                    "package_metadata": package.get("metadata", {}),
                    "package_cpes": package.get("cpes", []),
                    "package_purl": package.get("purl")
                }
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_sbom_for_concerns(self, artifacts: List[Dict], target: ScanTarget) -> List[Finding]:
        """Analyze SBOM for potential security concerns."""
        findings = []
        
        # Check for outdated or EOL packages
        outdated_packages = self._find_potentially_outdated_packages(artifacts)
        if outdated_packages:
            finding = Finding(
                id="SBOM-OUTDATED-PACKAGES",
                title="Potentially Outdated Packages Detected",
                description=f"Found {len(outdated_packages)} packages that may be outdated or end-of-life",
                severity=SeverityLevel.LOW,
                scanner=self.name,
                target=target.path,
                location=target.path,
                remediation="Review and update outdated packages to their latest versions",
                metadata={
                    "outdated_packages": outdated_packages[:10],  # Limit to first 10
                    "total_outdated": len(outdated_packages)
                }
            )
            findings.append(finding)
        
        # Check for packages with concerning licenses
        license_concerns = self._find_license_concerns(artifacts)
        if license_concerns:
            finding = Finding(
                id="SBOM-LICENSE-CONCERNS",
                title="Packages with Concerning Licenses",
                description=f"Found {len(license_concerns)} packages with potentially problematic licenses",
                severity=SeverityLevel.MEDIUM,
                scanner=self.name,
                target=target.path,
                location=target.path,
                remediation="Review license compatibility for packages with restrictive licenses",
                metadata={
                    "license_concerns": license_concerns[:10],  # Limit to first 10
                    "total_concerns": len(license_concerns)
                }
            )
            findings.append(finding)
        
        # Check for duplicate packages (different versions)
        duplicates = self._find_duplicate_packages(artifacts)
        if duplicates:
            finding = Finding(
                id="SBOM-DUPLICATE-PACKAGES",
                title="Duplicate Package Versions Detected",
                description=f"Found {len(duplicates)} packages with multiple versions",
                severity=SeverityLevel.LOW,
                scanner=self.name,
                target=target.path,
                location=target.path,
                remediation="Consider consolidating package versions to reduce attack surface",
                metadata={
                    "duplicate_packages": duplicates,
                    "total_duplicates": len(duplicates)
                }
            )
            findings.append(finding)
        
        return findings
    
    def _identify_important_packages(self, artifacts: List[Dict]) -> List[Dict]:
        """Identify packages that are important from a security perspective."""
        important = []
        
        # Security-sensitive package patterns
        security_patterns = [
            "openssl", "crypto", "ssl", "tls", "auth", "security",
            "kernel", "glibc", "libc", "systemd", "sudo", "ssh",
            "nginx", "apache", "httpd", "mysql", "postgres", "redis"
        ]
        
        for artifact in artifacts:
            name = artifact.get("name", "").lower()
            
            # Check if package name contains security-sensitive terms
            if any(pattern in name for pattern in security_patterns):
                important.append(artifact)
            
            # Include packages with known security implications
            if artifact.get("type") in ["deb", "rpm", "apk"] and name in [
                "bash", "curl", "wget", "git", "python", "node", "java"
            ]:
                important.append(artifact)
        
        return important[:20]  # Limit to 20 most important
    
    def _get_package_location(self, package: Dict) -> str:
        """Get location string for a package."""
        locations = package.get("locations", [])
        if locations and locations[0].get("path"):
            return locations[0]["path"]
        return package.get("name", "unknown")
    
    def _find_potentially_outdated_packages(self, artifacts: List[Dict]) -> List[Dict]:
        """Find packages that might be outdated (heuristic-based)."""
        outdated = []
        
        # Simple heuristics for potentially outdated packages
        for artifact in artifacts:
            version = artifact.get("version", "")
            name = artifact.get("name", "")
            
            # Very old version patterns (this is a simple heuristic)
            if version:
                # Check for very old major versions
                if any(version.startswith(old_ver) for old_ver in ["0.", "1.", "2."]):
                    # But exclude packages that are legitimately at these versions
                    if name not in ["zlib", "libpng", "libjpeg"]:
                        outdated.append({
                            "name": name,
                            "version": version,
                            "type": artifact.get("type"),
                            "reason": "potentially_old_version"
                        })
        
        return outdated
    
    def _find_license_concerns(self, artifacts: List[Dict]) -> List[Dict]:
        """Find packages with concerning licenses."""
        concerns = []
        
        concerning_licenses = [
            "GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL",
            "Copyleft", "Proprietary", "Commercial"
        ]
        
        for artifact in artifacts:
            licenses = artifact.get("licenses", [])
            for license_info in licenses:
                license_name = license_info if isinstance(license_info, str) else license_info.get("value", "")
                
                if any(concern in license_name.upper() for concern in concerning_licenses):
                    concerns.append({
                        "name": artifact.get("name"),
                        "version": artifact.get("version"),
                        "license": license_name,
                        "type": artifact.get("type")
                    })
                    break
        
        return concerns
    
    def _find_duplicate_packages(self, artifacts: List[Dict]) -> List[Dict]:
        """Find packages with multiple versions."""
        package_versions = {}
        
        for artifact in artifacts:
            name = artifact.get("name")
            version = artifact.get("version")
            
            if name and version:
                if name not in package_versions:
                    package_versions[name] = []
                package_versions[name].append(version)
        
        # Find packages with multiple versions
        duplicates = []
        for name, versions in package_versions.items():
            if len(set(versions)) > 1:  # Multiple unique versions
                duplicates.append({
                    "name": name,
                    "versions": list(set(versions))
                })
        
        return duplicates
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Syft typically returns 0 on success."""
        return return_code == 0