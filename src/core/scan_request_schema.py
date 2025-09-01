"""
JSON Schema for YAML scan request validation.
"""

SCAN_REQUEST_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "Security Scanner Scan Request Schema",
    "description": "Schema for validating YAML scan request files",
    "properties": {
        "scan_request": {
            "type": "object",
            "properties": {
                "id": {
                    "type": ["string", "null"],
                    "description": "Optional custom scan ID"
                },
                "description": {
                    "type": "string",
                    "description": "Human readable description of the scan",
                    "minLength": 1,
                    "maxLength": 200
                },
                "created_by": {
                    "type": ["string", "null"],
                    "description": "User or system that created this scan request"
                }
            },
            "additionalProperties": False
        },
        "targets": {
            "type": "object",
            "description": "Scan targets configuration",
            "properties": {
                "docker_images": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*(:[a-zA-Z0-9._-]+)?$"
                    },
                    "description": "List of Docker images to scan"
                },
                "git_repositories": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "List of Git repository paths to scan"
                },
                "kubernetes_manifests": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "List of Kubernetes manifest paths to scan"
                },
                "terraform_code": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "List of Terraform code paths to scan"
                },
                "filesystem_paths": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "List of filesystem paths to scan"
                }
            },
            "additionalProperties": False,
            "minProperties": 1
        },
        "scanners": {
            "type": "object",
            "description": "Scanner configurations",
            "properties": {
                "trivy": {"$ref": "#/definitions/scanner_config"},
                "grype": {"$ref": "#/definitions/scanner_config"},
                "syft": {"$ref": "#/definitions/scanner_config"},
                "semgrep": {"$ref": "#/definitions/scanner_config"},
                "trufflehog": {"$ref": "#/definitions/scanner_config"},
                "gitleaks": {"$ref": "#/definitions/scanner_config"},
                "checkov": {"$ref": "#/definitions/scanner_config"},
                "conftest": {"$ref": "#/definitions/scanner_config"},
                "dockle": {"$ref": "#/definitions/scanner_config"},
                "hadolint": {"$ref": "#/definitions/scanner_config"}
            },
            "additionalProperties": False,
            "minProperties": 1
        },
        "output": {
            "type": "object",
            "description": "Output configuration",
            "properties": {
                "base_dir": {
                    "type": "string",
                    "description": "Base directory for output reports",
                    "default": "security-reports"
                },
                "formats": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["json", "html", "sarif", "xml"]
                    },
                    "minItems": 1,
                    "description": "Output formats for reports"
                },
                "include_raw": {
                    "type": "boolean",
                    "description": "Include raw scanner output",
                    "default": True
                },
                "consolidate_reports": {
                    "type": "boolean",
                    "description": "Consolidate reports from multiple scanners",
                    "default": True
                },
                "generate_executive_summary": {
                    "type": "boolean",
                    "description": "Generate executive summary",
                    "default": True
                }
            },
            "additionalProperties": False
        },
        "execution": {
            "type": "object",
            "description": "Execution configuration",
            "properties": {
                "parallel_scans": {
                    "type": "boolean",
                    "description": "Run scans in parallel",
                    "default": True
                },
                "max_workers": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 32,
                    "description": "Maximum number of parallel workers",
                    "default": 4
                },
                "fail_on_high_severity": {
                    "type": "boolean",
                    "description": "Exit with error code on high/critical findings",
                    "default": False
                }
            },
            "additionalProperties": False
        },
        "logging": {
            "type": "object",
            "description": "Logging configuration",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    "description": "Logging level",
                    "default": "INFO"
                },
                "file": {
                    "type": ["string", "null"],
                    "description": "Log file path (null for console only)"
                }
            },
            "additionalProperties": False
        },
        "metadata": {
            "type": "object",
            "description": "Additional metadata for the scan request",
            "additionalProperties": True
        }
    },
    "required": ["targets", "scanners"],
    "additionalProperties": False,
    "definitions": {
        "scanner_config": {
            "type": "object",
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "description": "Whether this scanner is enabled",
                    "default": True
                },
                "timeout": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 7200,
                    "description": "Scanner timeout in seconds",
                    "default": 300
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Minimum severity threshold for reporting",
                    "default": "MEDIUM"
                },
                "additional_args": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Additional command-line arguments for the scanner"
                }
            },
            "additionalProperties": False
        }
    }
}

def get_schema() -> dict:
    """Get the JSON schema for scan request validation."""
    return SCAN_REQUEST_SCHEMA