"""
Target validation utilities for the security scanner.

This module provides comprehensive validation for all supported target types
before scanning begins, ensuring targets exist and are accessible.
"""

import os
import re
import subprocess
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

from ..core.models import ScanTarget, ScanTargetType
from ..core.exceptions import ConfigurationError


@dataclass
class ValidationResult:
    """Result of target validation."""
    is_valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}


class TargetValidator:
    """Validates scan targets before scanning."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the target validator.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Docker command timeout (seconds)
        self.docker_timeout = 30
        
        # Git command timeout (seconds)
        self.git_timeout = 30
        
        # Supported file extensions for different target types
        self.supported_extensions = {
            ScanTargetType.KUBERNETES_MANIFEST: {'.yaml', '.yml', '.json'},
            ScanTargetType.TERRAFORM_CODE: {'.tf', '.tfvars', '.hcl'}
        }
    
    def validate_target(self, target: ScanTarget) -> ValidationResult:
        """
        Validate a single scan target.
        
        Args:
            target: The target to validate
            
        Returns:
            ValidationResult with validation status and details
        """
        self.logger.debug(f"Validating target: {target.path} (type: {target.target_type.value})")
        
        try:
            # Route to appropriate validator based on target type
            if target.target_type == ScanTargetType.DOCKER_IMAGE:
                return self._validate_docker_image(target)
            elif target.target_type == ScanTargetType.GIT_REPOSITORY:
                return self._validate_git_repository(target)
            elif target.target_type == ScanTargetType.KUBERNETES_MANIFEST:
                return self._validate_kubernetes_manifest(target)
            elif target.target_type == ScanTargetType.TERRAFORM_CODE:
                return self._validate_terraform_code(target)
            elif target.target_type == ScanTargetType.FILESYSTEM:
                return self._validate_filesystem(target)
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unsupported target type: {target.target_type.value}"
                )
        
        except Exception as e:
            self.logger.error(f"Error validating target {target.path}: {e}")
            return ValidationResult(
                is_valid=False,
                error_message=f"Validation failed with error: {str(e)}"
            )
    
    def validate_targets(self, targets: List[ScanTarget]) -> Dict[str, ValidationResult]:
        """
        Validate multiple targets.
        
        Args:
            targets: List of targets to validate
            
        Returns:
            Dictionary mapping target paths to validation results
        """
        results = {}
        
        for target in targets:
            try:
                result = self.validate_target(target)
                results[target.path] = result
                
                if result.is_valid:
                    self.logger.info(f"✓ Target validated: {target.path}")
                    if result.warnings:
                        for warning in result.warnings:
                            self.logger.warning(f"⚠ Warning for {target.path}: {warning}")
                else:
                    self.logger.error(f"✗ Target validation failed: {target.path} - {result.error_message}")
            
            except Exception as e:
                self.logger.error(f"Error validating target {target.path}: {e}")
                results[target.path] = ValidationResult(
                    is_valid=False,
                    error_message=f"Validation error: {str(e)}"
                )
        
        return results
    
    def _validate_docker_image(self, target: ScanTarget) -> ValidationResult:
        """Validate Docker image target."""
        image_name = target.path
        
        # Basic format validation
        if not self._is_valid_docker_image_name(image_name):
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid Docker image name format: {image_name}"
            )
        
        # Check if Docker is available
        if not self._is_command_available("docker"):
            return ValidationResult(
                is_valid=False,
                error_message="Docker command is not available. Please install Docker."
            )
        
        # Try to pull or verify image exists
        try:
            # First try to inspect the image locally
            result = subprocess.run(
                ["docker", "image", "inspect", image_name],
                capture_output=True,
                text=True,
                timeout=self.docker_timeout
            )
            
            if result.returncode == 0:
                # Image exists locally
                return ValidationResult(
                    is_valid=True,
                    metadata={"image_source": "local", "image_name": image_name}
                )
            
            # If not local, try to pull the image
            self.logger.info(f"Attempting to pull Docker image: {image_name}")
            pull_result = subprocess.run(
                ["docker", "pull", image_name],
                capture_output=True,
                text=True,
                timeout=self.docker_timeout
            )
            
            if pull_result.returncode == 0:
                return ValidationResult(
                    is_valid=True,
                    metadata={"image_source": "pulled", "image_name": image_name}
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Failed to pull Docker image: {pull_result.stderr.strip()}"
                )
        
        except subprocess.TimeoutExpired:
            return ValidationResult(
                is_valid=False,
                error_message=f"Timeout validating Docker image: {image_name}"
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Error validating Docker image: {str(e)}"
            )
    
    def _validate_git_repository(self, target: ScanTarget) -> ValidationResult:
        """Validate Git repository target."""
        repo_path = target.path
        
        # Check if it's a URL or local path
        if self._is_url(repo_path):
            return self._validate_remote_git_repository(repo_path)
        else:
            return self._validate_local_git_repository(repo_path)
    
    def _validate_remote_git_repository(self, repo_url: str) -> ValidationResult:
        """Validate remote Git repository."""
        # Check if Git is available
        if not self._is_command_available("git"):
            return ValidationResult(
                is_valid=False,
                error_message="Git command is not available. Please install Git."
            )
        
        try:
            # Use git ls-remote to check if repository is accessible
            result = subprocess.run(
                ["git", "ls-remote", "--heads", repo_url],
                capture_output=True,
                text=True,
                timeout=self.git_timeout
            )
            
            if result.returncode == 0:
                return ValidationResult(
                    is_valid=True,
                    metadata={"repo_type": "remote", "repo_url": repo_url}
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Cannot access Git repository: {result.stderr.strip()}"
                )
        
        except subprocess.TimeoutExpired:
            return ValidationResult(
                is_valid=False,
                error_message=f"Timeout accessing Git repository: {repo_url}"
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Error validating Git repository: {str(e)}"
            )
    
    def _validate_local_git_repository(self, repo_path: str) -> ValidationResult:
        """Validate local Git repository."""
        path = Path(repo_path)
        
        # Check if path exists
        if not path.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Git repository path does not exist: {repo_path}"
            )
        
        # Check if it's a directory
        if not path.is_dir():
            return ValidationResult(
                is_valid=False,
                error_message=f"Git repository path is not a directory: {repo_path}"
            )
        
        # Check if it's a Git repository
        git_dir = path / ".git"
        if not git_dir.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Directory is not a Git repository (no .git folder): {repo_path}"
            )
        
        warnings = []
        metadata = {"repo_type": "local", "repo_path": str(path.absolute())}
        
        # Check for common issues
        if not os.access(path, os.R_OK):
            warnings.append("Repository directory is not readable")
        
        # Try to get some Git info
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                metadata["git_toplevel"] = result.stdout.strip()
        except:
            warnings.append("Could not determine Git repository information")
        
        return ValidationResult(
            is_valid=True,
            warnings=warnings,
            metadata=metadata
        )
    
    def _validate_kubernetes_manifest(self, target: ScanTarget) -> ValidationResult:
        """Validate Kubernetes manifest target."""
        return self._validate_structured_files(
            target,
            ScanTargetType.KUBERNETES_MANIFEST,
            ["apiVersion", "kind"],  # Required K8s fields
            "Kubernetes manifest"
        )
    
    def _validate_terraform_code(self, target: ScanTarget) -> ValidationResult:
        """Validate Terraform code target."""
        return self._validate_structured_files(
            target,
            ScanTargetType.TERRAFORM_CODE,
            [],  # No specific required fields for Terraform
            "Terraform code"
        )
    
    def _validate_structured_files(
        self,
        target: ScanTarget,
        target_type: ScanTargetType,
        required_fields: List[str],
        description: str
    ) -> ValidationResult:
        """Validate structured file targets (K8s, Terraform, etc.)."""
        path = Path(target.path)
        
        # Check if path exists
        if not path.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"{description} path does not exist: {target.path}"
            )
        
        warnings = []
        metadata = {"target_type": target_type.value, "files_found": []}
        
        if path.is_file():
            # Single file validation
            if not self._has_supported_extension(path, target_type):
                warnings.append(f"File extension may not be appropriate for {description}")
            
            if not self._is_file_readable(path):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File is not readable: {path}"
                )
            
            # Validate file content if required fields are specified
            if required_fields:
                content_valid, content_error = self._validate_file_content(path, required_fields)
                if not content_valid:
                    warnings.append(f"Content validation warning: {content_error}")
            
            metadata["files_found"] = [str(path)]
        
        elif path.is_dir():
            # Directory validation - find relevant files
            relevant_files = self._find_relevant_files(path, target_type)
            
            if not relevant_files:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"No {description} files found in directory: {path}"
                )
            
            # Check readability of files
            unreadable_files = []
            for file_path in relevant_files:
                if not self._is_file_readable(file_path):
                    unreadable_files.append(str(file_path))
            
            if unreadable_files:
                warnings.append(f"Some files are not readable: {', '.join(unreadable_files[:5])}")
            
            metadata["files_found"] = [str(f) for f in relevant_files]
            
            if len(relevant_files) > 100:
                warnings.append(f"Large number of files found ({len(relevant_files)}), scan may take longer")
        
        else:
            return ValidationResult(
                is_valid=False,
                error_message=f"Path is neither a file nor directory: {target.path}"
            )
        
        return ValidationResult(
            is_valid=True,
            warnings=warnings,
            metadata=metadata
        )
    
    def _validate_filesystem(self, target: ScanTarget) -> ValidationResult:
        """Validate filesystem target."""
        path = Path(target.path)
        
        # Check if path exists
        if not path.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Filesystem path does not exist: {target.path}"
            )
        
        # Check if it's readable
        if not os.access(path, os.R_OK):
            return ValidationResult(
                is_valid=False,
                error_message=f"Filesystem path is not readable: {target.path}"
            )
        
        warnings = []
        metadata = {"target_type": "filesystem", "path_type": "file" if path.is_file() else "directory"}
        
        if path.is_dir():
            # Count files for large directory warning
            try:
                file_count = sum(1 for _ in path.rglob("*") if _.is_file())
                metadata["estimated_file_count"] = file_count
                
                if file_count > 10000:
                    warnings.append(f"Large directory with {file_count} files, scan may be slow")
                elif file_count == 0:
                    warnings.append("Directory appears to be empty")
            except PermissionError:
                warnings.append("Could not count files in directory due to permission issues")
        
        return ValidationResult(
            is_valid=True,
            warnings=warnings,
            metadata=metadata
        )
    
    def _is_valid_docker_image_name(self, image_name: str) -> bool:
        """Check if Docker image name has valid format."""
        # Basic Docker image name validation
        # Format: [registry/]namespace/repository[:tag|@digest]
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(?:\:[0-9]+)?/)?(?:[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?/)*[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?(?:\:[a-zA-Z0-9][\w\.\-]{0,127})?(?:@sha256:[a-f0-9]{64})?$'
        return bool(re.match(pattern, image_name.lower())) or image_name.count('/') >= 1
    
    def _is_url(self, path: str) -> bool:
        """Check if path is a URL."""
        parsed = urllib.parse.urlparse(path)
        return parsed.scheme in ('http', 'https', 'git', 'ssh')
    
    def _is_command_available(self, command: str) -> bool:
        """Check if a command is available in PATH."""
        try:
            subprocess.run(
                [command, "--version"],
                capture_output=True,
                timeout=5
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def _has_supported_extension(self, file_path: Path, target_type: ScanTargetType) -> bool:
        """Check if file has supported extension for target type."""
        if target_type not in self.supported_extensions:
            return True  # No specific extensions required
        
        return file_path.suffix.lower() in self.supported_extensions[target_type]
    
    def _is_file_readable(self, file_path: Path) -> bool:
        """Check if file is readable."""
        try:
            return file_path.is_file() and os.access(file_path, os.R_OK)
        except:
            return False
    
    def _find_relevant_files(self, directory: Path, target_type: ScanTargetType) -> List[Path]:
        """Find relevant files in directory for target type."""
        relevant_files = []
        
        try:
            if target_type in self.supported_extensions:
                # Look for files with specific extensions
                extensions = self.supported_extensions[target_type]
                for ext in extensions:
                    relevant_files.extend(directory.rglob(f"*{ext}"))
            else:
                # For filesystem targets, include common source code files
                common_extensions = {
                    '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.h',
                    '.yaml', '.yml', '.json', '.xml', '.tf', '.tfvars', '.hcl',
                    '.dockerfile', '.sh', '.bat', '.ps1'
                }
                for ext in common_extensions:
                    relevant_files.extend(directory.rglob(f"*{ext}"))
                
                # Also include Dockerfile and docker-compose files
                relevant_files.extend(directory.rglob("Dockerfile*"))
                relevant_files.extend(directory.rglob("docker-compose*.yml"))
                relevant_files.extend(directory.rglob("docker-compose*.yaml"))
        
        except Exception as e:
            self.logger.warning(f"Error finding files in {directory}: {e}")
        
        return relevant_files
    
    def _validate_file_content(self, file_path: Path, required_fields: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate file content for required fields."""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            missing_fields = []
            for field in required_fields:
                if field not in content:
                    missing_fields.append(field)
            
            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"
            
            return True, None
        
        except Exception as e:
            return False, f"Error reading file: {str(e)}"
    
    def get_validation_summary(self, results: Dict[str, ValidationResult]) -> Dict[str, Any]:
        """Get summary of validation results."""
        total = len(results)
        valid = sum(1 for r in results.values() if r.is_valid)
        invalid = total - valid
        
        warnings_count = sum(len(r.warnings) for r in results.values() if r.warnings)
        
        return {
            "total_targets": total,
            "valid_targets": valid,
            "invalid_targets": invalid,
            "success_rate": f"{(valid/total)*100:.1f}%" if total > 0 else "0%",
            "total_warnings": warnings_count,
            "invalid_targets_details": {
                path: result.error_message 
                for path, result in results.items() 
                if not result.is_valid
            }
        }