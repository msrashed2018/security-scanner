"""
Enhanced configuration management for the security scanner service.
Supports JSON configuration files with dynamic scanner arguments and presets.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from pathlib import Path
import yaml
import json


@dataclass
class ScannerConfig:
    """Configuration for individual security scanners."""
    enabled: bool = True
    timeout: int = 300
    severity_threshold: str = "MEDIUM"
    additional_args: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class OutputConfig:
    """Configuration for output formatting and reporting."""
    base_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["json", "html"])
    include_raw: bool = True
    consolidate_reports: bool = True
    generate_executive_summary: bool = True


@dataclass
class ExecutionConfig:
    """Configuration for execution settings."""
    parallel_scans: bool = True
    max_workers: int = 4
    fail_on_high_severity: bool = False


@dataclass
class LoggingConfig:
    """Configuration for logging settings."""
    level: str = "INFO"
    file: Optional[str] = None


@dataclass
class ScanTargets:
    """Configuration for scan targets."""
    docker_images: List[str] = field(default_factory=list)
    git_repositories: List[str] = field(default_factory=list)
    kubernetes_manifests: List[str] = field(default_factory=list)
    terraform_code: List[str] = field(default_factory=list)
    filesystem_paths: List[str] = field(default_factory=list)


@dataclass
class PresetConfig:
    """Configuration for scanner presets."""
    description: str = ""
    scanners: List[str] = field(default_factory=list)
    timeout_multiplier: float = 1.0


@dataclass
class SecurityScanConfig:
    """Enhanced main configuration class for the security scanning service."""
    
    # Scan targets
    scan_targets: ScanTargets = field(default_factory=ScanTargets)
    
    # Scanner configurations - dynamically populated
    scanners: Dict[str, ScannerConfig] = field(default_factory=dict)
    
    # Configuration sections
    output: OutputConfig = field(default_factory=OutputConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    # Presets
    presets: Dict[str, PresetConfig] = field(default_factory=dict)
    
    # Metadata
    _metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize default scanner configurations if not provided."""
        if not self.scanners:
            self.scanners = self._get_default_scanner_configs()
    
    def _get_default_scanner_configs(self) -> Dict[str, ScannerConfig]:
        """Get default configurations for all supported scanners."""
        return {
            'trivy': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="HIGH",
                additional_args=["--timeout", "15m", "--dependency-tree", "--list-all-pkgs", "--ignore-unfixed"],
                description="Comprehensive security scanner for containers, filesystems, and Git repositories"
            ),
            'grype': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=[],
                description="Fast vulnerability scanner for container images and filesystems"
            ),
            'syft': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="INFO",
                additional_args=[],
                description="SBOM (Software Bill of Materials) generator"
            ),
            'dockle': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=[],
                description="Container image linter for security best practices"
            ),
            'hadolint': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=[],
                description="Dockerfile linter for best practices"
            ),
            'checkov': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=["--quiet"],
                description="Static code analysis for Infrastructure as Code"
            ),
            'kics': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=[],
                description="Security scanner for Infrastructure as Code"
            ),
            'conftest': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="MEDIUM",
                additional_args=[],
                description="Policy testing tool for structured configuration data"
            ),
            'trufflehog': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="HIGH",
                additional_args=["--no-verification", "--filter-entropy=3.0", "--concurrency=4"],
                description="Secrets scanner for Git repositories and Docker images"
            ),
            'gitleaks': ScannerConfig(
                enabled=True,
                timeout=300,
                severity_threshold="HIGH",
                additional_args=[],
                description="SAST tool for detecting secrets in Git repositories"
            ),
            'semgrep': ScannerConfig(
                enabled=True,
                timeout=600,
                severity_threshold="MEDIUM",
                additional_args=["--config=p/security-audit", "--config=p/cwe-top-25"],
                description="Multi-language SAST tool for finding bugs and security issues"
            )
        }
    
    # Legacy property accessors for backward compatibility
    @property
    def docker_images(self) -> List[str]:
        return self.scan_targets.docker_images
    
    @docker_images.setter
    def docker_images(self, value: List[str]):
        self.scan_targets.docker_images = value
    
    @property
    def git_repositories(self) -> List[str]:
        return self.scan_targets.git_repositories
    
    @git_repositories.setter
    def git_repositories(self, value: List[str]):
        self.scan_targets.git_repositories = value
    
    @property
    def kubernetes_manifests(self) -> List[str]:
        return self.scan_targets.kubernetes_manifests
    
    @kubernetes_manifests.setter
    def kubernetes_manifests(self, value: List[str]):
        self.scan_targets.kubernetes_manifests = value
    
    @property
    def terraform_code(self) -> List[str]:
        return self.scan_targets.terraform_code
    
    @terraform_code.setter
    def terraform_code(self, value: List[str]):
        self.scan_targets.terraform_code = value
    
    @property
    def filesystem_paths(self) -> List[str]:
        return self.scan_targets.filesystem_paths
    
    @filesystem_paths.setter
    def filesystem_paths(self, value: List[str]):
        self.scan_targets.filesystem_paths = value
    
    @property
    def parallel_scans(self) -> bool:
        return self.execution.parallel_scans
    
    @parallel_scans.setter
    def parallel_scans(self, value: bool):
        self.execution.parallel_scans = value
    
    @property
    def max_workers(self) -> int:
        return self.execution.max_workers
    
    @max_workers.setter
    def max_workers(self, value: int):
        self.execution.max_workers = value
    
    @property
    def log_level(self) -> str:
        return self.logging.level
    
    @log_level.setter
    def log_level(self, value: str):
        self.logging.level = value
    
    @property
    def fail_on_high_severity(self) -> bool:
        return self.execution.fail_on_high_severity
    
    @fail_on_high_severity.setter
    def fail_on_high_severity(self, value: bool):
        self.execution.fail_on_high_severity = value
    
    # Legacy scanner property accessors
    def __getattr__(self, name: str):
        """Dynamic access to scanner configurations for backward compatibility."""
        if name in self.scanners:
            return self.scanners[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    @classmethod
    def from_file(cls, config_path: str) -> 'SecurityScanConfig':
        """Load configuration from YAML or JSON file."""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r') as f:
            if config_file.suffix.lower() in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif config_file.suffix.lower() == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SecurityScanConfig':
        """Create configuration from dictionary with enhanced support for dynamic scanners."""
        config = cls()
        
        # Handle metadata
        if '_metadata' in data:
            config._metadata = data['_metadata']
        
        # Handle scan targets
        if 'scan_targets' in data:
            config.scan_targets = ScanTargets(**data['scan_targets'])
        
        # Handle legacy format for backward compatibility
        legacy_targets = ['docker_images', 'git_repositories', 'kubernetes_manifests', 'terraform_code', 'filesystem_paths']
        for target in legacy_targets:
            if target in data:
                setattr(config.scan_targets, target, data[target])
        
        # Handle scanner configurations
        if 'scanners' in data:
            for scanner_name, scanner_data in data['scanners'].items():
                config.scanners[scanner_name] = ScannerConfig(**scanner_data)
        
        # Handle legacy scanner format
        default_scanners = config._get_default_scanner_configs()
        for scanner_name in default_scanners.keys():
            if scanner_name in data:
                config.scanners[scanner_name] = ScannerConfig(**data[scanner_name])
        
        # Handle output configuration
        if 'output' in data:
            config.output = OutputConfig(**data['output'])
        
        # Handle execution configuration
        if 'execution' in data:
            config.execution = ExecutionConfig(**data['execution'])
        
        # Handle logging configuration
        if 'logging' in data:
            config.logging = LoggingConfig(**data['logging'])
        
        # Handle presets
        if 'presets' in data:
            for preset_name, preset_data in data['presets'].items():
                config.presets[preset_name] = PresetConfig(**preset_data)
        
        # Handle legacy execution fields
        legacy_execution = ['parallel_scans', 'max_workers', 'fail_on_high_severity']
        for field in legacy_execution:
            if field in data:
                setattr(config.execution, field, data[field])
        
        # Handle legacy logging fields
        if 'log_level' in data:
            config.logging.level = data['log_level']
        
        return config
    
    def apply_preset(self, preset_name: str) -> None:
        """Apply a preset configuration to the scanner settings."""
        if preset_name not in self.presets:
            raise ValueError(f"Unknown preset: {preset_name}. Available presets: {list(self.presets.keys())}")
        
        preset = self.presets[preset_name]
        
        # Disable all scanners first
        for scanner_config in self.scanners.values():
            scanner_config.enabled = False
        
        # Enable only preset scanners
        for scanner_name in preset.scanners:
            if scanner_name in self.scanners:
                scanner_config = self.scanners[scanner_name]
                scanner_config.enabled = True
                # Apply timeout multiplier
                original_timeout = scanner_config.timeout
                scanner_config.timeout = int(original_timeout * preset.timeout_multiplier)
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary."""
        result = {}
        
        # Add scanner configurations
        for scanner_name in ['trivy', 'grype', 'syft', 'dockle', 'hadolint', 
                           'checkov', 'kics', 'conftest', 'trufflehog', 'gitleaks', 'semgrep']:
            scanner_config = getattr(self, scanner_name)
            result[scanner_name] = {
                'enabled': scanner_config.enabled,
                'timeout': scanner_config.timeout,
                'severity_threshold': scanner_config.severity_threshold,
                'additional_args': scanner_config.additional_args,
                'output_formats': scanner_config.output_formats
            }
        
        # Add output configuration
        result['output'] = {
            'base_dir': self.output.base_dir,
            'formats': self.output.formats,
            'include_raw': self.output.include_raw,
            'consolidate_reports': self.output.consolidate_reports,
            'generate_executive_summary': self.output.generate_executive_summary
        }
        
        # Add other fields
        result.update({
            'docker_images': self.docker_images,
            'git_repositories': self.git_repositories,
            'kubernetes_manifests': self.kubernetes_manifests,
            'terraform_code': self.terraform_code,
            'parallel_scans': self.parallel_scans,
            'max_workers': self.max_workers,
            'log_level': self.log_level,
            'fail_on_high_severity': self.fail_on_high_severity
        })
        
        return result
    
    def save_to_file(self, config_path: str) -> None:
        """Save configuration to file."""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = self.to_dict()
        
        with open(config_file, 'w') as f:
            if config_file.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(data, f, default_flow_style=False, indent=2)
            elif config_file.suffix.lower() == '.json':
                json.dump(data, f, indent=2)
            else:
                raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")
    
    def get_enabled_scanners(self) -> Set[str]:
        """Get list of enabled scanners."""
        enabled = set()
        for scanner_name in ['trivy', 'grype', 'syft', 'dockle', 'hadolint', 
                           'checkov', 'kics', 'conftest', 'trufflehog', 'gitleaks', 'semgrep']:
            scanner_config = getattr(self, scanner_name)
            if scanner_config.enabled:
                enabled.add(scanner_name)
        return enabled


def get_default_config() -> SecurityScanConfig:
    """Get default configuration with sensible defaults."""
    return SecurityScanConfig()


def load_config_from_env() -> SecurityScanConfig:
    """Load configuration from environment variables."""
    config = SecurityScanConfig()
    
    # Override with environment variables if present
    if os.getenv('SECURITY_SCAN_LOG_LEVEL'):
        config.log_level = os.getenv('SECURITY_SCAN_LOG_LEVEL')
    
    if os.getenv('SECURITY_SCAN_OUTPUT_DIR'):
        config.output.base_dir = os.getenv('SECURITY_SCAN_OUTPUT_DIR')
    
    if os.getenv('SECURITY_SCAN_MAX_WORKERS'):
        config.max_workers = int(os.getenv('SECURITY_SCAN_MAX_WORKERS'))
    
    if os.getenv('SECURITY_SCAN_FAIL_ON_HIGH'):
        config.fail_on_high_severity = os.getenv('SECURITY_SCAN_FAIL_ON_HIGH').lower() == 'true'
    
    return config