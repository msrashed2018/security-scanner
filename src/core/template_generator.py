"""
Template generator for creating YAML scan request templates.
"""

from typing import Dict, Any
import yaml


class TemplateGenerator:
    """Generate YAML templates for different use cases"""
    
    def __init__(self):
        self.templates = {
            'basic-scan': self._basic_template,
            'full-audit': self._full_audit_template,
            'container-scan': self._container_template,
            'source-code-scan': self._source_code_template,
            'infrastructure-scan': self._infrastructure_template,
            'secrets-scan': self._secrets_template,
            'ci-cd': self._ci_cd_template,
            'development': self._development_template
        }
    
    def generate_template(self, template_type: str) -> str:
        """Generate a template by type"""
        if template_type not in self.templates:
            available = ', '.join(self.templates.keys())
            raise ValueError(f"Unknown template type '{template_type}'. Available: {available}")
        
        template_data = self.templates[template_type]()
        return yaml.dump(template_data, default_flow_style=False, indent=2, sort_keys=False)
    
    def list_templates(self) -> list[str]:
        """List all available template types"""
        return list(self.templates.keys())
    
    def _basic_template(self) -> Dict[str, Any]:
        """Basic scan template with common scanners"""
        return {
            'scan_request': {
                'description': 'Basic security scan with essential scanners'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': ['.'],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'trivy': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'MEDIUM'
                },
                'grype': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                'semgrep': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': [
                        '--config=p/security-audit'
                    ]
                }
            },
            'output': {
                'base_dir': 'security-reports',
                'formats': ['json', 'html'],
                'include_raw': True,
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 2,
                'fail_on_high_severity': False
            },
            'logging': {
                'level': 'INFO',
                'file': None
            }
        }
    
    def _full_audit_template(self) -> Dict[str, Any]:
        """Comprehensive security audit template"""
        return {
            'scan_request': {
                'description': 'Comprehensive security audit with all scanners'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': ['.'],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'trivy': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--dependency-tree',
                        '--list-all-pkgs',
                        '--ignore-unfixed'
                    ]
                },
                'grype': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'MEDIUM'
                },
                'syft': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'INFO'
                },
                'semgrep': {
                    'enabled': True,
                    'timeout': 1200,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': [
                        '--config=p/security-audit',
                        '--config=p/owasp-top-10',
                        '--config=p/cwe-top-25'
                    ]
                },
                'trufflehog': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--no-verification',
                        '--filter-entropy=3.0'
                    ]
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH'
                },
                'checkov': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': ['--quiet']
                },
                'dockle': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'MEDIUM'
                },
                'hadolint': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                }
            },
            'output': {
                'base_dir': 'comprehensive-security-audit',
                'formats': ['json', 'html', 'sarif'],
                'include_raw': True,
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 6,
                'fail_on_high_severity': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'security-audit.log'
            }
        }
    
    def _container_template(self) -> Dict[str, Any]:
        """Container-focused scanning template"""
        return {
            'scan_request': {
                'description': 'Container security scan focusing on Docker images'
            },
            'targets': {
                'docker_images': ['nginx:latest'],
                'git_repositories': [],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'trivy': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--dependency-tree',
                        '--list-all-pkgs'
                    ]
                },
                'grype': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                'syft': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'INFO'
                },
                'dockle': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                'hadolint': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                # Disable non-container scanners
                'semgrep': {'enabled': False},
                'trufflehog': {'enabled': False},
                'gitleaks': {'enabled': False},
                'checkov': {'enabled': False}
            },
            'output': {
                'base_dir': 'container-security-reports',
                'formats': ['json', 'html', 'sarif'],
                'include_raw': True,
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 4,
                'fail_on_high_severity': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'container-scan.log'
            }
        }
    
    def _source_code_template(self) -> Dict[str, Any]:
        """Source code scanning template with SAST focus"""
        return {
            'scan_request': {
                'description': 'Source code security analysis with SAST and secrets detection'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': ['.'],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'semgrep': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': [
                        '--config=p/security-audit',
                        '--config=p/owasp-top-10',
                        '--config=p/cwe-top-25'
                    ]
                },
                'trufflehog': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--no-verification',
                        '--filter-entropy=3.0'
                    ]
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'HIGH'
                },
                'trivy': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': ['--dependency-tree']
                },
                'grype': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                # Disable container-specific scanners
                'dockle': {'enabled': False},
                'hadolint': {'enabled': False},
                'checkov': {'enabled': False}
            },
            'output': {
                'base_dir': 'source-code-security-reports',
                'formats': ['json', 'html', 'sarif'],
                'include_raw': True,
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 4,
                'fail_on_high_severity': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'source-code-scan.log'
            }
        }
    
    def _infrastructure_template(self) -> Dict[str, Any]:
        """Infrastructure as code scanning template"""
        return {
            'scan_request': {
                'description': 'Infrastructure as Code security analysis'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': [],
                'kubernetes_manifests': ['./k8s/'],
                'terraform_code': ['./terraform/'],
                'filesystem_paths': []
            },
            'scanners': {
                'checkov': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'MEDIUM',
                    'additional_args': ['--quiet']
                },
                'hadolint': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'MEDIUM'
                },
                'trufflehog': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH'
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'HIGH'
                },
                # Disable non-IaC scanners
                'trivy': {'enabled': False},
                'grype': {'enabled': False},
                'syft': {'enabled': False},
                'dockle': {'enabled': False},
                'semgrep': {'enabled': False}
            },
            'output': {
                'base_dir': 'infrastructure-security-reports',
                'formats': ['json', 'html', 'sarif'],
                'include_raw': True,
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 3,
                'fail_on_high_severity': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'infrastructure-scan.log'
            }
        }
    
    def _secrets_template(self) -> Dict[str, Any]:
        """Secrets detection focused template"""
        return {
            'scan_request': {
                'description': 'Secrets detection scan for sensitive data'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': ['.'],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'trufflehog': {
                    'enabled': True,
                    'timeout': 900,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--no-verification',
                        '--filter-entropy=3.0',
                        '--concurrency=6'
                    ]
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH',
                    'additional_args': ['--verbose']
                },
                # Disable all other scanners
                'trivy': {'enabled': False},
                'grype': {'enabled': False},
                'syft': {'enabled': False},
                'dockle': {'enabled': False},
                'hadolint': {'enabled': False},
                'checkov': {'enabled': False},
                'semgrep': {'enabled': False}
            },
            'output': {
                'base_dir': 'secrets-scan-reports',
                'formats': ['json', 'html'],
                'include_raw': False,  # Raw output may contain actual secrets
                'generate_executive_summary': True
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 2,
                'fail_on_high_severity': True
            },
            'logging': {
                'level': 'WARNING',
                'file': 'secrets-scan.log'
            },
            'metadata': {
                'scan_type': 'secrets-detection',
                'compliance': ['pci-dss', 'hipaa', 'sox']
            }
        }
    
    def _ci_cd_template(self) -> Dict[str, Any]:
        """CI/CD optimized template"""
        return {
            'scan_request': {
                'description': 'CI/CD security scan - fast and focused',
                'created_by': 'ci-cd-pipeline'
            },
            'targets': {
                'docker_images': [],
                'git_repositories': ['.'],
                'kubernetes_manifests': [],
                'terraform_code': [],
                'filesystem_paths': []
            },
            'scanners': {
                'trivy': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'HIGH',
                    'additional_args': ['--ignore-unfixed']
                },
                'semgrep': {
                    'enabled': True,
                    'timeout': 600,
                    'severity_threshold': 'HIGH',
                    'additional_args': [
                        '--config=p/security-audit',
                        '--timeout=300'
                    ]
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 180,
                    'severity_threshold': 'HIGH'
                },
                # Disable slower scanners for CI/CD speed
                'grype': {'enabled': False},
                'syft': {'enabled': False},
                'trufflehog': {'enabled': False},
                'dockle': {'enabled': False},
                'hadolint': {'enabled': False},
                'checkov': {'enabled': False}
            },
            'output': {
                'base_dir': 'ci-cd-security-reports',
                'formats': ['sarif', 'json'],
                'include_raw': False,
                'generate_executive_summary': False
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 4,
                'fail_on_high_severity': True
            },
            'logging': {
                'level': 'WARNING',
                'file': None
            },
            'metadata': {
                'environment': 'ci-cd',
                'optimized_for': 'speed'
            }
        }
    
    def _development_template(self) -> Dict[str, Any]:
        """Development workflow template"""
        return {
            'scan_request': {
                'description': 'Development workflow security check'
            },
            'targets': {
                'git_repositories': ['.']
            },
            'scanners': {
                'semgrep': {
                    'enabled': True,
                    'timeout': 300,
                    'severity_threshold': 'HIGH',
                    'additional_args': ['--config=p/security-audit']
                },
                'trufflehog': {
                    'enabled': True,
                    'timeout': 180,
                    'severity_threshold': 'HIGH',
                    'additional_args': ['--since-commit=HEAD~5']
                },
                'gitleaks': {
                    'enabled': True,
                    'timeout': 120,
                    'severity_threshold': 'HIGH'
                },
                # Disable slower scanners
                'trivy': {'enabled': False},
                'grype': {'enabled': False},
                'syft': {'enabled': False},
                'dockle': {'enabled': False},
                'hadolint': {'enabled': False},
                'checkov': {'enabled': False}
            },
            'output': {
                'base_dir': 'dev-security-check',
                'formats': ['json'],
                'include_raw': False,
                'generate_executive_summary': False
            },
            'execution': {
                'parallel_scans': True,
                'max_workers': 2,
                'fail_on_high_severity': False
            },
            'logging': {
                'level': 'WARNING',
                'file': None
            }
        }