"""
YAML-based scan request model for the security scanner.
This replaces the CLI argument parsing approach with a declarative configuration.
"""

import os
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

try:
    import jsonschema
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

from .config import SecurityScanConfig, ScannerConfig, OutputConfig
from .models import ScanTarget, ScanTargetType
from .exceptions import ConfigurationError
from .scan_request_schema import get_schema


@dataclass
class ScanRequestMeta:
    """Metadata for scan request"""
    id: Optional[str] = None
    description: str = ""
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class ScanTargets:
    """Scan targets configuration"""
    docker_images: List[str] = field(default_factory=list)
    git_repositories: List[str] = field(default_factory=list)
    kubernetes_manifests: List[str] = field(default_factory=list)
    terraform_code: List[str] = field(default_factory=list)
    filesystem_paths: List[str] = field(default_factory=list)


@dataclass
class ExecutionConfig:
    """Execution configuration"""
    parallel_scans: bool = True
    max_workers: int = 4
    fail_on_high_severity: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: Optional[str] = None


@dataclass
class ScanRequest:
    """YAML-based scan request configuration"""
    scan_request: ScanRequestMeta = field(default_factory=ScanRequestMeta)
    targets: ScanTargets = field(default_factory=ScanTargets)
    scanners: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    output: Dict[str, Any] = field(default_factory=dict)
    execution: Dict[str, Any] = field(default_factory=dict)
    logging: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'ScanRequest':
        """Load scan request from YAML file"""
        yaml_file = Path(yaml_path)
        
        if not yaml_file.exists():
            raise ConfigurationError(f"Scan request file not found: {yaml_path}")
        
        if not yaml_file.is_file():
            raise ConfigurationError(f"Path is not a file: {yaml_path}")
        
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {yaml_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error reading {yaml_path}: {e}")
        
        if not isinstance(data, dict):
            raise ConfigurationError(f"YAML file must contain a dictionary: {yaml_path}")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanRequest':
        """Create scan request from dictionary"""
        # Parse scan_request metadata
        scan_request_data = data.get('scan_request', {})
        scan_request_meta = ScanRequestMeta(
            id=scan_request_data.get('id'),
            description=scan_request_data.get('description', ''),
            created_by=scan_request_data.get('created_by'),
        )
        
        # Parse targets
        targets_data = data.get('targets', {})
        targets = ScanTargets(
            docker_images=targets_data.get('docker_images', []),
            git_repositories=targets_data.get('git_repositories', []),
            kubernetes_manifests=targets_data.get('kubernetes_manifests', []),
            terraform_code=targets_data.get('terraform_code', []),
            filesystem_paths=targets_data.get('filesystem_paths', [])
        )
        
        return cls(
            scan_request=scan_request_meta,
            targets=targets,
            scanners=data.get('scanners', {}),
            output=data.get('output', {}),
            execution=data.get('execution', {}),
            logging=data.get('logging', {}),
            metadata=data.get('metadata', {})
        )
    
    def validate(self) -> List[str]:
        """Validate scan request and return validation errors"""
        errors = []
        
        # Schema validation if jsonschema is available
        if JSONSCHEMA_AVAILABLE:
            try:
                schema = get_schema()
                data = self._to_dict_for_validation()
                jsonschema.validate(data, schema)
            except jsonschema.ValidationError as e:
                # Convert jsonschema error to readable format
                if e.absolute_path:
                    field_path = '.'.join(str(p) for p in e.absolute_path)
                    errors.append(f"Field '{field_path}': {e.message}")
                else:
                    errors.append(f"Schema validation: {e.message}")
            except Exception as e:
                errors.append(f"Schema validation error: {e}")
        else:
            # Basic validation if jsonschema is not available
            errors.extend(self._basic_validation())
        
        # Additional business logic validation
        errors.extend(self._business_validation())
        
        return errors
    
    def _to_dict_for_validation(self) -> Dict[str, Any]:
        """Convert to dictionary for schema validation"""
        return {
            'scan_request': {
                'id': self.scan_request.id,
                'description': self.scan_request.description,
                'created_by': self.scan_request.created_by
            },
            'targets': {
                'docker_images': self.targets.docker_images,
                'git_repositories': self.targets.git_repositories,
                'kubernetes_manifests': self.targets.kubernetes_manifests,
                'terraform_code': self.targets.terraform_code,
                'filesystem_paths': self.targets.filesystem_paths
            },
            'scanners': self.scanners,
            'output': self.output,
            'execution': self.execution,
            'logging': self.logging,
            'metadata': self.metadata
        }
    
    def _basic_validation(self) -> List[str]:
        """Basic validation when jsonschema is not available"""
        errors = []
        
        # Check that at least one target is specified
        has_targets = any([
            self.targets.docker_images,
            self.targets.git_repositories,
            self.targets.kubernetes_manifests,
            self.targets.terraform_code,
            self.targets.filesystem_paths
        ])
        
        if not has_targets:
            errors.append("At least one scan target must be specified")
        
        # Validate scanner configuration
        if not self.scanners:
            errors.append("At least one scanner must be configured")
        
        # Check that at least one scanner is enabled
        enabled_scanners = []
        for scanner_name, scanner_config in self.scanners.items():
            if isinstance(scanner_config, dict) and scanner_config.get('enabled', True):
                enabled_scanners.append(scanner_name)
        
        if not enabled_scanners:
            errors.append("At least one scanner must be enabled")
        
        # Validate execution settings
        execution = self.execution
        if 'max_workers' in execution:
            max_workers = execution['max_workers']
            if not isinstance(max_workers, int) or max_workers < 1:
                errors.append("max_workers must be a positive integer")
        
        # Validate logging settings
        logging_config = self.logging
        if 'level' in logging_config:
            level = logging_config['level']
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if level not in valid_levels:
                errors.append(f"Invalid log level '{level}'. Valid levels: {valid_levels}")
        
        # Validate output settings
        output = self.output
        if 'formats' in output:
            formats = output['formats']
            if not isinstance(formats, list) or not formats:
                errors.append("output.formats must be a non-empty list")
            else:
                valid_formats = ['json', 'html', 'sarif', 'xml']
                for fmt in formats:
                    if fmt not in valid_formats:
                        errors.append(f"Invalid output format '{fmt}'. Valid formats: {valid_formats}")
        
        return errors
    
    def _business_validation(self) -> List[str]:
        """Business logic validation"""
        errors = []
        
        # Validate paths exist
        all_paths = []
        all_paths.extend(self.targets.git_repositories)
        all_paths.extend(self.targets.kubernetes_manifests)
        all_paths.extend(self.targets.terraform_code)
        all_paths.extend(self.targets.filesystem_paths)
        
        for path in all_paths:
            if not Path(path).exists():
                errors.append(f"Path does not exist: {path}")
        
        # Validate scanner names
        valid_scanners = [
            'trivy', 'grype', 'syft', 'semgrep', 'trufflehog', 'gitleaks',
            'checkov', 'conftest', 'dockle', 'hadolint'
        ]
        
        for scanner_name in self.scanners.keys():
            if scanner_name not in valid_scanners:
                errors.append(f"Unknown scanner '{scanner_name}'. Valid scanners: {valid_scanners}")
        
        return errors
    
    def to_security_scan_config(self) -> SecurityScanConfig:
        """Convert to internal SecurityScanConfig format"""
        config = SecurityScanConfig()
        
        # Set targets
        config.docker_images = self.targets.docker_images
        config.git_repositories = self.targets.git_repositories
        config.kubernetes_manifests = self.targets.kubernetes_manifests
        config.terraform_code = self.targets.terraform_code
        config.filesystem_paths = self.targets.filesystem_paths
        
        # Configure scanners
        for scanner_name, scanner_data in self.scanners.items():
            if scanner_name in config.scanners:
                scanner_config = config.scanners[scanner_name]
                scanner_config.enabled = scanner_data.get('enabled', True)
                scanner_config.timeout = scanner_data.get('timeout', scanner_config.timeout)
                scanner_config.severity_threshold = scanner_data.get('severity_threshold', scanner_config.severity_threshold)
                scanner_config.additional_args = scanner_data.get('additional_args', scanner_config.additional_args)
        
        # Configure output
        if self.output:
            if 'base_dir' in self.output:
                config.output.base_dir = self.output['base_dir']
            if 'formats' in self.output:
                config.output.formats = self.output['formats']
            if 'include_raw' in self.output:
                config.output.include_raw = self.output['include_raw']
            if 'generate_executive_summary' in self.output:
                config.output.generate_executive_summary = self.output['generate_executive_summary']
        
        # Configure execution
        if self.execution:
            if 'parallel_scans' in self.execution:
                config.execution.parallel_scans = self.execution['parallel_scans']
            if 'max_workers' in self.execution:
                config.execution.max_workers = self.execution['max_workers']
            if 'fail_on_high_severity' in self.execution:
                config.execution.fail_on_high_severity = self.execution['fail_on_high_severity']
        
        # Configure logging
        if self.logging:
            if 'level' in self.logging:
                config.logging.level = self.logging['level']
            if 'file' in self.logging:
                config.logging.file = self.logging['file']
        
        return config
    
    def create_scan_targets(self) -> List[ScanTarget]:
        """Create ScanTarget objects from configuration"""
        targets = []
        
        # Docker images
        for image in self.targets.docker_images:
            targets.append(ScanTarget(
                path=image,
                target_type=ScanTargetType.DOCKER_IMAGE,
                name=image.split('/')[-1].split(':')[0]
            ))
        
        # Git repositories
        for repo in self.targets.git_repositories:
            targets.append(ScanTarget(
                path=repo,
                target_type=ScanTargetType.GIT_REPOSITORY,
                name=Path(repo).name
            ))
        
        # Kubernetes manifests
        for manifest in self.targets.kubernetes_manifests:
            targets.append(ScanTarget(
                path=manifest,
                target_type=ScanTargetType.KUBERNETES_MANIFEST,
                name=Path(manifest).name
            ))
        
        # Terraform code
        for terraform in self.targets.terraform_code:
            targets.append(ScanTarget(
                path=terraform,
                target_type=ScanTargetType.TERRAFORM_CODE,
                name=Path(terraform).name
            ))
        
        # Filesystem paths
        for filesystem_path in self.targets.filesystem_paths:
            targets.append(ScanTarget(
                path=filesystem_path,
                target_type=ScanTargetType.FILESYSTEM,
                name=Path(filesystem_path).name
            ))
        
        return targets
    
    def generate_scan_id(self) -> str:
        """Generate a scan ID for this request"""
        if self.scan_request.id:
            return self.scan_request.id
        
        # Generate based on description or timestamp
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        if self.scan_request.description:
            # Create a safe filename from description
            safe_desc = "".join(c for c in self.scan_request.description if c.isalnum() or c in (' ', '-', '_')).rstrip()
            safe_desc = safe_desc.replace(' ', '-').lower()[:20]
            return f"{safe_desc}-{timestamp}"
        else:
            return f"scan-{timestamp}"