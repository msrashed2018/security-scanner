"""
Semgrep scanner implementation.

Semgrep is a fast, open-source static analysis tool for finding bugs, detecting dependency
vulnerabilities, and enforcing code standards at editor, commit, and CI time.
"""

import json
from typing import List, Dict, Any
import os

from .base import BaseScanner
from ..core.models import ScanResult, ScanTarget, Finding, SeverityLevel
from ..core.config import ScannerConfig


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner implementation."""

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def supported_targets(self) -> List[str]:
        return [
            "git_repository",
            "filesystem"
        ]

    @property
    def required_tools(self) -> List[str]:
        return ["semgrep"]

    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """Execute Semgrep scan."""

        # Build command based on target type
        command = self._build_command(target)

        # Execute scan
        result = self._run_command(command)

        # Parse results
        findings = self._parse_semgrep_output(result.stdout, target)

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
                "rulesets_used": self._get_applicable_rulesets(target),
                "language_detection": self._detect_languages(target)
            }
        )

    def _build_command(self, target: ScanTarget) -> List[str]:
        """Build Semgrep command."""
        command = [
            "semgrep",
            "--json",
            "--quiet",
            "--timeout", str(self.config.timeout)
        ]

        # Add rulesets
        rulesets = self._get_applicable_rulesets(target)
        for ruleset in rulesets:
            command.extend(["--config", ruleset])

        # Add severity filter if configured
        if self.config.severity_threshold != "INFO":
            severity_map = {
                "CRITICAL": "ERROR",
                "HIGH": "ERROR",
                "MEDIUM": "WARNING",
                "LOW": "INFO",
                "INFO": "INFO"
            }
            min_severity = severity_map.get(self.config.severity_threshold, "INFO")
            command.extend([f"--severity={min_severity}"])

        # Add additional arguments from config
        command.extend(self.config.additional_args)

        # Add target path
        command.append(target.path)

        return command

    def _get_applicable_rulesets(self, target: ScanTarget) -> List[str]:
        """Get applicable Semgrep rulesets based on target."""
        base_rulesets = [
            "p/security-audit",
            "p/cwe-top-25"
        ]

        # Detect languages in the target
        languages = self._detect_languages(target)

        # Add language-specific rulesets
        for lang in languages:
            if lang == "python":
                base_rulesets.append("p/python")
            elif lang == "javascript":
                base_rulesets.append("p/javascript")
            elif lang == "typescript":
                base_rulesets.append("p/javascript")  # TypeScript uses JS rules
            elif lang == "java":
                base_rulesets.append("p/java")
            elif lang == "go":
                base_rulesets.append("p/golang")
            elif lang == "ruby":
                base_rulesets.append("p/ruby")
            elif lang == "php":
                base_rulesets.append("p/php")
            elif lang == "csharp":
                base_rulesets.append("p/csharp")
            elif lang == "kotlin":
                base_rulesets.append("p/java")  # Kotlin uses Java rules
            elif lang == "scala":
                base_rulesets.append("p/java")  # Scala uses Java rules

        return base_rulesets

    def _detect_languages(self, target: ScanTarget) -> List[str]:
        """Detect programming languages in the target."""
        languages = set()

        # Walk through the target directory
        for root, dirs, files in os.walk(target.path):
            for file in files:
                if file.endswith('.py'):
                    languages.add('python')
                elif file.endswith(('.js', '.jsx')):
                    languages.add('javascript')
                elif file.endswith(('.ts', '.tsx')):
                    languages.add('typescript')
                elif file.endswith('.java'):
                    languages.add('java')
                elif file.endswith('.go'):
                    languages.add('go')
                elif file.endswith('.rb'):
                    languages.add('ruby')
                elif file.endswith(('.php', '.phtml')):
                    languages.add('php')
                elif file.endswith(('.cs', '.csx')):
                    languages.add('csharp')
                elif file.endswith('.kt'):
                    languages.add('kotlin')
                elif file.endswith('.scala'):
                    languages.add('scala')

        return list(languages)

    def _filter_config_args(self, args: List[str]) -> List[str]:
        """Filter out --config arguments from additional_args since we handle them separately."""
        filtered = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--config" and i + 1 < len(args):
                # Skip --config and its value
                i += 2
            elif arg.startswith("--config="):
                # Skip --config=value format
                i += 1
            else:
                # Keep other arguments
                filtered.append(arg)
                i += 1
        return filtered

    def _parse_semgrep_output(self, output: str, target: ScanTarget) -> List[Finding]:
        """Parse Semgrep JSON output into Finding objects."""
        findings = []

        try:
            data = self._parse_json_output(output)

            if "results" in data:
                for result in data["results"]:
                    finding = self._create_finding_from_result(result, target)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            self.logger.error(f"Failed to parse Semgrep output: {e}")

        return findings

    def _create_finding_from_result(self, result: Dict[str, Any], target: ScanTarget) -> Finding:
        """Create a Finding object from a Semgrep result."""

        # Extract basic information
        check_id = result.get("check_id", "UNKNOWN")
        path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)

        # Build location string
        location = f"{path}:{start_line}"
        if start_line != end_line:
            location = f"{path}:{start_line}-{end_line}"

        # Extract severity
        severity = self._map_semgrep_severity(result.get("severity", "INFO"))

        # Extract message and description from the extra field
        extra = result.get("extra", {})
        message = extra.get("message", "")
        description = extra.get("description", message)

        # Extract metadata from the extra field
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", [])
        owasp = metadata.get("owasp", [])
        confidence = metadata.get("confidence", "UNKNOWN")

        # Extract code snippet - try to get actual line content
        code_snippet = self._extract_code_snippet(path, start_line, end_line)

        # Build remediation advice
        remediation = self._build_remediation_advice(result)

        finding = Finding(
            id=f"SEMGREP-{check_id}",
            title=f"Semgrep: {message[:100]}{'...' if len(message) > 100 else ''}",
            description=description,
            severity=severity,
            scanner=self.name,
            target=target.path,
            location=location,
            remediation=remediation,
            metadata={
                "check_id": check_id,
                "rule_source": metadata.get("source", "semgrep"),
                "confidence": confidence,
                "category": metadata.get("category"),
                "cwe": cwe,
                "owasp": owasp,
                "technology": metadata.get("technology", []),
                "references": metadata.get("references", []),
                "file_path": path,
                "start_line": start_line,
                "end_line": end_line,
                "code_snippet": code_snippet,
                "fix": extra.get("fix", "")
            }
        )

        return finding

    def _map_semgrep_severity(self, severity: str) -> SeverityLevel:
        """Map Semgrep severity levels to SeverityLevel enum."""
        severity_map = {
            "ERROR": SeverityLevel.HIGH,
            "WARNING": SeverityLevel.MEDIUM,
            "INFO": SeverityLevel.LOW,
            "UNKNOWN": SeverityLevel.UNKNOWN
        }
        return severity_map.get(severity.upper(), SeverityLevel.UNKNOWN)

    def _build_remediation_advice(self, result: Dict[str, Any]) -> str:
        """Build remediation advice for a Semgrep finding."""
        advice_parts = []

        # Check if there's a fix available
        fix = result.get("fix")
        if fix:
            advice_parts.append(f"Apply the suggested fix: {fix}")

        # Add general advice based on category
        metadata = result.get("metadata", {})
        category = metadata.get("category", "").lower()

        if "security" in category:
            advice_parts.append("Review the code for potential security vulnerabilities")
            advice_parts.append("Consider input validation and sanitization")
        elif "performance" in category:
            advice_parts.append("Review the code for performance optimizations")
        elif "maintainability" in category:
            advice_parts.append("Consider refactoring for better code maintainability")
        elif "correctness" in category:
            advice_parts.append("Review the logic for potential bugs or errors")

        # Add references if available
        references = metadata.get("references", [])
        if references:
            advice_parts.append(f"See: {', '.join(references[:2])}")  # Limit to 2 references

        # Add CWE/OWASP specific advice
        cwe = metadata.get("cwe", [])
        if cwe:
            advice_parts.append(f"Related CWE: {', '.join(cwe[:2])}")

        owasp = metadata.get("owasp", [])
        if owasp:
            advice_parts.append(f"Related OWASP: {', '.join(owasp[:2])}")

        return ". ".join(advice_parts) if advice_parts else "Review the code and apply appropriate fixes"

    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """Semgrep returns non-zero when findings are detected."""
        # Semgrep returns 0 for no findings, 1 for findings, >1 for errors
        return return_code in [0, 1]

    def _filter_config_args(self, args: List[str]) -> List[str]:
        """Filter out --config arguments from additional_args since we handle them separately."""
        filtered = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--config" and i + 1 < len(args):
                # Skip --config and its value
                i += 2
            elif arg.startswith("--config="):
                # Skip --config=value format
                i += 1
            else:
                # Keep other arguments
                filtered.append(arg)
                i += 1
        return filtered