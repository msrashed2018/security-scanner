"""
Unit tests for target validator utilities.
"""

import os
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import pytest
import logging

# Import the modules to test
from src.core.models import ScanTarget, ScanTargetType
from src.utils.target_validator import TargetValidator, ValidationResult


class TestValidationResult:
    """Test ValidationResult dataclass."""
    
    def test_validation_result_creation(self):
        """Test creating ValidationResult instances."""
        # Valid result
        result = ValidationResult(is_valid=True)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.warnings == []
        assert result.metadata == {}
        
        # Invalid result with error
        result = ValidationResult(
            is_valid=False,
            error_message="Test error",
            warnings=["Warning 1"],
            metadata={"key": "value"}
        )
        assert result.is_valid is False
        assert result.error_message == "Test error"
        assert result.warnings == ["Warning 1"]
        assert result.metadata == {"key": "value"}


class TestTargetValidator:
    """Test TargetValidator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = TargetValidator(logger=logging.getLogger('test'))
        self.temp_dir = None
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_temp_directory(self):
        """Create temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
        return Path(self.temp_dir)
    
    def test_init(self):
        """Test validator initialization."""
        validator = TargetValidator()
        assert validator.docker_timeout == 30
        assert validator.git_timeout == 30
        assert ScanTargetType.KUBERNETES_MANIFEST in validator.supported_extensions
        assert ScanTargetType.TERRAFORM_CODE in validator.supported_extensions
    
    def test_validate_target_unsupported_type(self):
        """Test validation with unsupported target type."""
        # Mock an unsupported target type
        target = ScanTarget(path="/test/path", target_type=ScanTargetType.FILESYSTEM)
        target.target_type = "unsupported_type"  # Force invalid type
        
        with patch.object(target, 'target_type') as mock_type:
            mock_type.value = "unsupported_type"
            result = self.validator.validate_target(target)
        
        assert result.is_valid is False
        assert "Unsupported target type" in result.error_message
    
    def test_validate_target_exception_handling(self):
        """Test validation exception handling."""
        target = ScanTarget(path="/test/path", target_type=ScanTargetType.FILESYSTEM)
        
        with patch.object(self.validator, '_validate_filesystem', side_effect=Exception("Test error")):
            result = self.validator.validate_target(target)
        
        assert result.is_valid is False
        assert "Validation failed with error: Test error" in result.error_message
    
    def test_validate_targets_multiple(self):
        """Test validating multiple targets."""
        temp_dir = self.create_temp_directory()
        valid_file = temp_dir / "test.yaml"
        valid_file.write_text("apiVersion: v1\nkind: Pod")
        
        targets = [
            ScanTarget(path=str(valid_file), target_type=ScanTargetType.KUBERNETES_MANIFEST),
            ScanTarget(path="/nonexistent/path", target_type=ScanTargetType.FILESYSTEM)
        ]
        
        results = self.validator.validate_targets(targets)
        
        assert len(results) == 2
        assert results[str(valid_file)].is_valid is True
        assert results["/nonexistent/path"].is_valid is False
    
    # Docker Image Validation Tests
    
    def test_is_valid_docker_image_name(self):
        """Test Docker image name validation."""
        # Valid names
        valid_names = [
            "nginx",
            "nginx:latest",
            "library/nginx",
            "docker.io/library/nginx:1.21",
            "gcr.io/project/image:tag",
            "localhost:5000/myimage",
            "registry.example.com/namespace/image:v1.0.0"
        ]
        
        for name in valid_names:
            assert self.validator._is_valid_docker_image_name(name), f"Should be valid: {name}"
        
        # Invalid names (basic validation)
        invalid_names = [
            "",
            "UPPERCASE",
            "image::",
            "image name with spaces"
        ]
        
        for name in invalid_names:
            assert not self.validator._is_valid_docker_image_name(name), f"Should be invalid: {name}"
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_invalid_name(self, mock_cmd_available, mock_run):
        """Test Docker image validation with invalid name."""
        target = ScanTarget(path="INVALID IMAGE NAME", target_type=ScanTargetType.DOCKER_IMAGE)
        
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is False
        assert "Invalid Docker image name format" in result.error_message
    
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_no_docker(self, mock_cmd_available):
        """Test Docker image validation without Docker installed."""
        mock_cmd_available.return_value = False
        target = ScanTarget(path="nginx:latest", target_type=ScanTargetType.DOCKER_IMAGE)
        
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is False
        assert "Docker command is not available" in result.error_message
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_local_exists(self, mock_cmd_available, mock_run):
        """Test Docker image validation with locally existing image."""
        mock_cmd_available.return_value = True
        mock_run.return_value.returncode = 0
        
        target = ScanTarget(path="nginx:latest", target_type=ScanTargetType.DOCKER_IMAGE)
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is True
        assert result.metadata["image_source"] == "local"
        assert result.metadata["image_name"] == "nginx:latest"
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_pull_success(self, mock_cmd_available, mock_run):
        """Test Docker image validation with successful pull."""
        mock_cmd_available.return_value = True
        # First call (inspect) fails, second call (pull) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect fails
            MagicMock(returncode=0)   # pull succeeds
        ]
        
        target = ScanTarget(path="nginx:latest", target_type=ScanTargetType.DOCKER_IMAGE)
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is True
        assert result.metadata["image_source"] == "pulled"
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_pull_fails(self, mock_cmd_available, mock_run):
        """Test Docker image validation with failed pull."""
        mock_cmd_available.return_value = True
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect fails
            MagicMock(returncode=1, stderr="Error: image not found")  # pull fails
        ]
        
        target = ScanTarget(path="nonexistent:latest", target_type=ScanTargetType.DOCKER_IMAGE)
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is False
        assert "Failed to pull Docker image" in result.error_message
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_docker_image_timeout(self, mock_cmd_available, mock_run):
        """Test Docker image validation timeout."""
        mock_cmd_available.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)
        
        target = ScanTarget(path="nginx:latest", target_type=ScanTargetType.DOCKER_IMAGE)
        result = self.validator._validate_docker_image(target)
        
        assert result.is_valid is False
        assert "Timeout validating Docker image" in result.error_message
    
    # Git Repository Validation Tests
    
    def test_is_url(self):
        """Test URL detection."""
        urls = [
            "https://github.com/user/repo.git",
            "http://example.com/repo",
            "git@github.com:user/repo.git",
            "ssh://git@server/repo"
        ]
        
        for url in urls:
            assert self.validator._is_url(url), f"Should be URL: {url}"
        
        paths = [
            "/local/path",
            "relative/path",
            "./local/path",
            "~/home/path"
        ]
        
        for path in paths:
            assert not self.validator._is_url(path), f"Should not be URL: {path}"
    
    @patch.object(TargetValidator, '_validate_remote_git_repository')
    def test_validate_git_repository_remote(self, mock_validate_remote):
        """Test Git repository validation routes to remote validator."""
        mock_validate_remote.return_value = ValidationResult(is_valid=True)
        
        target = ScanTarget(path="https://github.com/user/repo.git", target_type=ScanTargetType.GIT_REPOSITORY)
        result = self.validator._validate_git_repository(target)
        
        mock_validate_remote.assert_called_once_with("https://github.com/user/repo.git")
        assert result.is_valid is True
    
    @patch.object(TargetValidator, '_validate_local_git_repository')
    def test_validate_git_repository_local(self, mock_validate_local):
        """Test Git repository validation routes to local validator."""
        mock_validate_local.return_value = ValidationResult(is_valid=True)
        
        target = ScanTarget(path="/local/repo", target_type=ScanTargetType.GIT_REPOSITORY)
        result = self.validator._validate_git_repository(target)
        
        mock_validate_local.assert_called_once_with("/local/repo")
        assert result.is_valid is True
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_remote_git_repository_no_git(self, mock_cmd_available, mock_run):
        """Test remote Git validation without Git installed."""
        mock_cmd_available.return_value = False
        
        result = self.validator._validate_remote_git_repository("https://github.com/user/repo.git")
        
        assert result.is_valid is False
        assert "Git command is not available" in result.error_message
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_remote_git_repository_success(self, mock_cmd_available, mock_run):
        """Test successful remote Git validation."""
        mock_cmd_available.return_value = True
        mock_run.return_value.returncode = 0
        
        result = self.validator._validate_remote_git_repository("https://github.com/user/repo.git")
        
        assert result.is_valid is True
        assert result.metadata["repo_type"] == "remote"
        assert result.metadata["repo_url"] == "https://github.com/user/repo.git"
    
    @patch('subprocess.run')
    @patch.object(TargetValidator, '_is_command_available')
    def test_validate_remote_git_repository_fails(self, mock_cmd_available, mock_run):
        """Test failed remote Git validation."""
        mock_cmd_available.return_value = True
        mock_run.return_value = MagicMock(returncode=1, stderr="fatal: repository not found")
        
        result = self.validator._validate_remote_git_repository("https://github.com/user/nonexistent.git")
        
        assert result.is_valid is False
        assert "Cannot access Git repository" in result.error_message
    
    def test_validate_local_git_repository_not_exists(self):
        """Test local Git validation with non-existent path."""
        result = self.validator._validate_local_git_repository("/nonexistent/path")
        
        assert result.is_valid is False
        assert "Git repository path does not exist" in result.error_message
    
    def test_validate_local_git_repository_not_directory(self):
        """Test local Git validation with file instead of directory."""
        temp_dir = self.create_temp_directory()
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")
        
        result = self.validator._validate_local_git_repository(str(test_file))
        
        assert result.is_valid is False
        assert "Git repository path is not a directory" in result.error_message
    
    def test_validate_local_git_repository_not_git_repo(self):
        """Test local Git validation with directory that's not a Git repo."""
        temp_dir = self.create_temp_directory()
        
        result = self.validator._validate_local_git_repository(str(temp_dir))
        
        assert result.is_valid is False
        assert "Directory is not a Git repository" in result.error_message
    
    def test_validate_local_git_repository_success(self):
        """Test successful local Git validation."""
        temp_dir = self.create_temp_directory()
        git_dir = temp_dir / ".git"
        git_dir.mkdir()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=str(temp_dir))
            result = self.validator._validate_local_git_repository(str(temp_dir))
        
        assert result.is_valid is True
        assert result.metadata["repo_type"] == "local"
        assert str(temp_dir) in result.metadata["repo_path"]
    
    # Filesystem Validation Tests
    
    def test_validate_filesystem_not_exists(self):
        """Test filesystem validation with non-existent path."""
        target = ScanTarget(path="/nonexistent/path", target_type=ScanTargetType.FILESYSTEM)
        result = self.validator._validate_filesystem(target)
        
        assert result.is_valid is False
        assert "Filesystem path does not exist" in result.error_message
    
    def test_validate_filesystem_success_file(self):
        """Test successful filesystem validation with file."""
        temp_dir = self.create_temp_directory()
        test_file = temp_dir / "test.py"
        test_file.write_text("print('hello')")
        
        target = ScanTarget(path=str(test_file), target_type=ScanTargetType.FILESYSTEM)
        result = self.validator._validate_filesystem(target)
        
        assert result.is_valid is True
        assert result.metadata["path_type"] == "file"
    
    def test_validate_filesystem_success_directory(self):
        """Test successful filesystem validation with directory."""
        temp_dir = self.create_temp_directory()
        # Create some test files
        (temp_dir / "test.py").write_text("print('hello')")
        (temp_dir / "test.js").write_text("console.log('hello');")
        
        target = ScanTarget(path=str(temp_dir), target_type=ScanTargetType.FILESYSTEM)
        result = self.validator._validate_filesystem(target)
        
        assert result.is_valid is True
        assert result.metadata["path_type"] == "directory"
        assert result.metadata["estimated_file_count"] == 2
    
    def test_validate_filesystem_large_directory_warning(self):
        """Test filesystem validation with large directory warning."""
        temp_dir = self.create_temp_directory()
        
        with patch('pathlib.Path.rglob') as mock_rglob:
            # Mock a large number of files
            mock_rglob.return_value = [MagicMock(is_file=lambda: True)] * 15000
            
            target = ScanTarget(path=str(temp_dir), target_type=ScanTargetType.FILESYSTEM)
            result = self.validator._validate_filesystem(target)
        
        assert result.is_valid is True
        assert any("Large directory" in warning for warning in result.warnings)
        assert result.metadata["estimated_file_count"] == 15000
    
    # Structured Files Validation Tests
    
    def test_has_supported_extension(self):
        """Test supported extension checking."""
        # Kubernetes files
        k8s_files = [
            Path("deployment.yaml"),
            Path("service.yml"),
            Path("config.json")
        ]
        for f in k8s_files:
            assert self.validator._has_supported_extension(f, ScanTargetType.KUBERNETES_MANIFEST)
        
        # Terraform files  
        tf_files = [
            Path("main.tf"),
            Path("variables.tfvars"),
            Path("config.hcl")
        ]
        for f in tf_files:
            assert self.validator._has_supported_extension(f, ScanTargetType.TERRAFORM_CODE)
        
        # Unsupported extension
        assert not self.validator._has_supported_extension(Path("test.txt"), ScanTargetType.KUBERNETES_MANIFEST)
    
    def test_validate_kubernetes_manifest_file(self):
        """Test Kubernetes manifest file validation."""
        temp_dir = self.create_temp_directory()
        k8s_file = temp_dir / "deployment.yaml"
        k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test")
        
        target = ScanTarget(path=str(k8s_file), target_type=ScanTargetType.KUBERNETES_MANIFEST)
        result = self.validator._validate_kubernetes_manifest(target)
        
        assert result.is_valid is True
        assert str(k8s_file) in result.metadata["files_found"]
    
    def test_validate_kubernetes_manifest_directory(self):
        """Test Kubernetes manifest directory validation."""
        temp_dir = self.create_temp_directory()
        
        # Create some K8s files
        (temp_dir / "deployment.yaml").write_text("apiVersion: apps/v1\nkind: Deployment")
        (temp_dir / "service.yml").write_text("apiVersion: v1\nkind: Service")
        (temp_dir / "configmap.json").write_text('{"apiVersion": "v1", "kind": "ConfigMap"}')
        
        target = ScanTarget(path=str(temp_dir), target_type=ScanTargetType.KUBERNETES_MANIFEST)
        result = self.validator._validate_kubernetes_manifest(target)
        
        assert result.is_valid is True
        assert len(result.metadata["files_found"]) == 3
    
    def test_validate_kubernetes_manifest_no_files(self):
        """Test Kubernetes manifest validation with no relevant files."""
        temp_dir = self.create_temp_directory()
        (temp_dir / "readme.txt").write_text("This is a readme")
        
        target = ScanTarget(path=str(temp_dir), target_type=ScanTargetType.KUBERNETES_MANIFEST)
        result = self.validator._validate_kubernetes_manifest(target)
        
        assert result.is_valid is False
        assert "No Kubernetes manifest files found" in result.error_message
    
    def test_validate_terraform_code(self):
        """Test Terraform code validation."""
        temp_dir = self.create_temp_directory()
        tf_file = temp_dir / "main.tf"
        tf_file.write_text('resource "aws_instance" "example" {\n  ami = "ami-12345"\n}')
        
        target = ScanTarget(path=str(tf_file), target_type=ScanTargetType.TERRAFORM_CODE)
        result = self.validator._validate_terraform_code(target)
        
        assert result.is_valid is True
        assert str(tf_file) in result.metadata["files_found"]
    
    # Utility Methods Tests
    
    def test_is_command_available(self):
        """Test command availability checking."""
        # Test with a command that should exist
        assert self.validator._is_command_available("python3") or self.validator._is_command_available("python")
        
        # Test with a command that shouldn't exist
        assert not self.validator._is_command_available("nonexistent_command_12345")
    
    def test_is_file_readable(self):
        """Test file readability checking."""
        temp_dir = self.create_temp_directory()
        readable_file = temp_dir / "readable.txt"
        readable_file.write_text("test content")
        
        assert self.validator._is_file_readable(readable_file)
        assert not self.validator._is_file_readable(Path("/nonexistent/file.txt"))
    
    def test_find_relevant_files(self):
        """Test finding relevant files in directory."""
        temp_dir = self.create_temp_directory()
        
        # Create various file types
        (temp_dir / "app.py").write_text("print('hello')")
        (temp_dir / "config.yaml").write_text("key: value")
        (temp_dir / "main.tf").write_text("resource {}")
        (temp_dir / "readme.txt").write_text("readme")
        (temp_dir / "Dockerfile").write_text("FROM ubuntu")
        
        # Test Kubernetes files
        k8s_files = self.validator._find_relevant_files(temp_dir, ScanTargetType.KUBERNETES_MANIFEST)
        k8s_file_names = [f.name for f in k8s_files]
        assert "config.yaml" in k8s_file_names
        
        # Test Terraform files
        tf_files = self.validator._find_relevant_files(temp_dir, ScanTargetType.TERRAFORM_CODE)
        tf_file_names = [f.name for f in tf_files]
        assert "main.tf" in tf_file_names
        
        # Test filesystem (should find all relevant files)
        fs_files = self.validator._find_relevant_files(temp_dir, ScanTargetType.FILESYSTEM)
        fs_file_names = [f.name for f in fs_files]
        assert "app.py" in fs_file_names
        assert "Dockerfile" in fs_file_names
    
    def test_validate_file_content(self):
        """Test file content validation."""
        temp_dir = self.create_temp_directory()
        
        # Create file with required fields
        valid_file = temp_dir / "valid.yaml"
        valid_file.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test")
        
        # Create file missing required fields
        invalid_file = temp_dir / "invalid.yaml"
        invalid_file.write_text("metadata:\n  name: test")
        
        # Test valid file
        is_valid, error = self.validator._validate_file_content(valid_file, ["apiVersion", "kind"])
        assert is_valid is True
        assert error is None
        
        # Test invalid file
        is_valid, error = self.validator._validate_file_content(invalid_file, ["apiVersion", "kind"])
        assert is_valid is False
        assert "Missing required fields: apiVersion" in error
    
    def test_get_validation_summary(self):
        """Test validation results summary."""
        results = {
            "/path/1": ValidationResult(is_valid=True, warnings=["Warning 1"]),
            "/path/2": ValidationResult(is_valid=False, error_message="Error 2"),
            "/path/3": ValidationResult(is_valid=True, warnings=["Warning 3", "Warning 4"])
        }
        
        summary = self.validator.get_validation_summary(results)
        
        assert summary["total_targets"] == 3
        assert summary["valid_targets"] == 2
        assert summary["invalid_targets"] == 1
        assert summary["success_rate"] == "66.7%"
        assert summary["total_warnings"] == 3
        assert "/path/2" in summary["invalid_targets_details"]
        assert summary["invalid_targets_details"]["/path/2"] == "Error 2"


# Integration tests
class TestTargetValidatorIntegration:
    """Integration tests for target validator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = TargetValidator(logger=logging.getLogger('integration_test'))
        self.temp_dir = None
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_temp_directory(self):
        """Create temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
        return Path(self.temp_dir)
    
    def test_validate_mixed_targets(self):
        """Test validating a mix of different target types."""
        temp_dir = self.create_temp_directory()
        
        # Create test files
        k8s_file = temp_dir / "deployment.yaml"
        k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment")
        
        tf_file = temp_dir / "main.tf"
        tf_file.write_text('resource "aws_instance" "test" {}')
        
        python_file = temp_dir / "app.py"
        python_file.write_text("print('hello world')")
        
        # Create targets
        targets = [
            ScanTarget(path=str(k8s_file), target_type=ScanTargetType.KUBERNETES_MANIFEST),
            ScanTarget(path=str(tf_file), target_type=ScanTargetType.TERRAFORM_CODE),
            ScanTarget(path=str(temp_dir), target_type=ScanTargetType.FILESYSTEM),
            ScanTarget(path="/nonexistent", target_type=ScanTargetType.FILESYSTEM)
        ]
        
        results = self.validator.validate_targets(targets)
        
        # Check results
        assert len(results) == 4
        assert results[str(k8s_file)].is_valid is True
        assert results[str(tf_file)].is_valid is True
        assert results[str(temp_dir)].is_valid is True
        assert results["/nonexistent"].is_valid is False
        
        # Check summary
        summary = self.validator.get_validation_summary(results)
        assert summary["total_targets"] == 4
        assert summary["valid_targets"] == 3
        assert summary["invalid_targets"] == 1
        assert summary["success_rate"] == "75.0%"


if __name__ == "__main__":
    pytest.main([__file__])