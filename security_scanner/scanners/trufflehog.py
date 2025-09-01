"""
TruffleHog scanner implementation.

TruffleHog searches for secrets in Git repositories, Docker images, and filesystems.
It uses 800+ detectors to find API keys, passwords, tokens, and other sensitive data.
"""

import json
from typing import List, Dict, Any
import tempfile
import subprocess

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class TruffleHogScanner(BaseScanner):
    """TruffleHog secrets scanner implementation."""
    
    @property
    def name(self) -> str:
        return "trufflehog"
    
    @property
    def supported_targets(self) -> List[str]:
        return [
            "docker_image",
            "git_repository",
            "filesystem"
        ]
    
    @property
    def required_tools(self) -> List[str]:
        return ["trufflehog"]
    
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute TruffleHog scan."""
        
        # Build command based on target type
        if target.target_type.value == "docker_image":
            command = self._build_docker_command(target)
        elif target.target_type.value == "git_repository":
            command = self._build_git_command(target)
        else:  # filesystem
            command = self._build_filesystem_command(target)
        
        # Execute scan
        result = self._run_command(command)
        
        # Parse results
        findings = self._parse_trufflehog_output(result.stdout, target)
        
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
    
    def _build_docker_command(self, target: ScanTarget) -> List[str]:
        """Build TruffleHog command for Docker image scanning."""
        command = [
            "trufflehog",
            "docker",
            "--image", target.path,
            "--json",
            "--no-update"
        ]
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        return command
    
    def _build_git_command(self, target: ScanTarget) -> List[str]:
        """Build TruffleHog command for Git repository scanning."""
        command = [
            "trufflehog",
            "git",
            target.path,
            "--json",
            "--no-update"
        ]
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        return command
    
    def _build_filesystem_command(self, target: ScanTarget) -> List[str]:
        """Build TruffleHog command for filesystem scanning."""
        command = [
            "trufflehog",
            "filesystem",
            target.path,
            "--json",
            "--no-update"
        ]
        
        # Add additional arguments from config
        command.extend(self.config.additional_args)
        
        return command
    
    def _parse_trufflehog_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse TruffleHog JSON Lines output into Finding objects."""
        findings = []
        
        if not output.strip():
            return findings
        
        # TruffleHog outputs JSON Lines format (one JSON object per line)
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                secret_data = json.loads(line)
                # Skip info messages
                if secret_data.get("level") == "info-0":
                    continue
                finding = self._create_finding_from_secret(secret_data, target)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse TruffleHog output line: {e}")
                continue
            except Exception as e:
                self.logger.error(f"Error processing TruffleHog finding: {e}")
                continue
        
        return findings
    
    def _create_finding_from_secret(self, secret_data: Dict[str, Any], target: ScanTarget) -> Finding:
        """Create a Finding object from TruffleHog secret data."""
        
        # Extract basic information
        detector_name = secret_data.get("DetectorName", "Unknown")
        raw_secret = secret_data.get("Raw", "")
        verified = secret_data.get("Verified", False)
        
        # Extract source metadata
        source_metadata = secret_data.get("SourceMetadata", {})
        source_data = source_metadata.get("Data", {})
        
        # Build location string
        location = self._build_location_string(source_data, target)
        
        # Determine severity based on verification and detector type
        severity = self._determine_secret_severity(detector_name, verified, raw_secret)
        
        # Build title and description
        title = f"Secret detected: {detector_name}"
        if verified:
            title += " (VERIFIED)"
        
        description = f"Potential {detector_name} secret found"
        if verified:
            description += " and verified as valid"
        
        # Truncate raw secret for security
        truncated_secret = self._truncate_secret(raw_secret)
        
        # Build remediation advice
        remediation = self._build_remediation_advice(detector_name, verified)
        
        finding = Finding(
            id=f"SECRET-{detector_name}-{hash(raw_secret) % 10000:04d}",
            title=title,
            description=description,
            severity=severity,
            scanner=self.name,
            target=target.path,
            location=location,
            remediation=remediation,
            metadata={
                "detector_name": detector_name,
                "detector_type": secret_data.get("DetectorType"),
                "verified": verified,
                "raw_secret_truncated": truncated_secret,
                "raw_secret_length": len(raw_secret),
                "source_type": source_metadata.get("Type"),
                "source_name": source_metadata.get("Name"),
                "source_id": source_metadata.get("ID"),
                "source_email": source_metadata.get("Email"),
                "source_timestamp": source_metadata.get("Timestamp"),
                "source_line": source_data.get("Line"),
                "source_commit": source_data.get("Commit"),
                "source_file": source_data.get("File"),
                "source_link": source_data.get("Link"),
                "extra_data": secret_data.get("ExtraData", {})
            }
        )
        
        return finding
    
    def _build_location_string(self, source_data: Dict[str, Any], target: ScanTarget) -> str:
        """Build location string from source data."""
        location_parts = []
        
        # Add file path if available
        if source_data.get("File"):
            location_parts.append(source_data["File"])
        
        # Add line number if available
        if source_data.get("Line"):
            location_parts.append(f"line:{source_data['Line']}")
        
        # Add commit if available (for Git repos)
        if source_data.get("Commit"):
            commit = source_data["Commit"][:8]  # Short commit hash
            location_parts.append(f"commit:{commit}")
        
        # Add Docker-specific information
        if target.target_type.value == "docker_image":
            docker_data = source_data.get("Docker", {})
            if docker_data.get("file"):
                location_parts.append(f"docker:{docker_data['file']}")
            elif docker_data.get("layer"):
                layer = docker_data["layer"][:12]  # Short layer ID
                location_parts.append(f"layer:{layer}")
        
        return ":".join(location_parts) if location_parts else "unknown"
    
    def _determine_secret_severity(self, detector_name: str, verified: bool, raw_secret: str) -> SeverityLevel:
        """Determine severity level for a secret."""
        
        # Verified secrets are always high severity
        if verified:
            return SeverityLevel.HIGH
        
        # High-impact secret types
        high_impact_detectors = [
            "AWS", "Azure", "GCP", "Google", "GitHub", "GitLab",
            "Slack", "Discord", "Telegram", "Twitter", "Facebook",
            "Stripe", "PayPal", "Square", "Twilio", "SendGrid",
            "Database", "MySQL", "PostgreSQL", "MongoDB", "Redis",
            "Private Key", "SSH", "RSA", "Certificate"
        ]
        
        if any(detector.lower() in detector_name.lower() for detector in high_impact_detectors):
            return SeverityLevel.HIGH
        
        # Medium impact for other API keys and tokens
        medium_impact_patterns = ["api", "key", "token", "secret", "password", "credential"]
        if any(pattern in detector_name.lower() for pattern in medium_impact_patterns):
            return SeverityLevel.MEDIUM
        
        # Check secret characteristics
        if len(raw_secret) > 32:  # Long secrets are more likely to be real
            return SeverityLevel.MEDIUM
        
        return SeverityLevel.LOW
    
    def _truncate_secret(self, secret: str, max_length: int = 20) -> str:
        """Truncate secret for safe logging."""
        if len(secret) <= max_length:
            return secret[:max_length//2] + "***" + secret[-max_length//2:]
        else:
            return secret[:max_length//2] + "***" + secret[-max_length//2:]
    
    def _build_remediation_advice(self, detector_name: str, verified: bool) -> str:
        """Build remediation advice for a secret."""
        advice_parts = []
        
        if verified:
            advice_parts.append("IMMEDIATE ACTION REQUIRED: This secret has been verified as valid")
            advice_parts.append("1. Revoke/rotate the secret immediately")
            advice_parts.append("2. Remove the secret from the codebase")
            advice_parts.append("3. Use environment variables or secret management systems")
        else:
            advice_parts.append("1. Verify if this is a real secret")
            advice_parts.append("2. If real, revoke/rotate the secret")
            advice_parts.append("3. Remove from codebase and use proper secret management")
        
        # Add detector-specific advice
        detector_lower = detector_name.lower()
        if "aws" in detector_lower:
            advice_parts.append("4. Check AWS CloudTrail for unauthorized usage")
            advice_parts.append("5. Consider using AWS IAM roles instead of access keys")
        elif "github" in detector_lower:
            advice_parts.append("4. Check GitHub audit logs for unauthorized access")
            advice_parts.append("5. Use GitHub Apps or fine-grained tokens")
        elif "private" in detector_lower and "key" in detector_lower:
            advice_parts.append("4. Generate new key pair")
            advice_parts.append("5. Update authorized_keys files")
        
        return ". ".join(advice_parts)
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """TruffleHog returns 0 for success, may return non-zero for various reasons."""
        # TruffleHog can return non-zero for various reasons, but still produce valid output
        return return_code in [0, 1, 2]  # Accept common return codes