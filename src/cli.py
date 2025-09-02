"""
Simplified command-line interface for the security scanner service.
YAML-configuration driven approach.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional
import uuid
from datetime import datetime

from .core.scan_request import ScanRequest
from .core.logging_config import setup_logging, configure_third_party_loggers
from .core.exceptions import SecurityScannerError, ConfigurationError
from .core.template_generator import TemplateGenerator
from .scanner_service import SecurityScannerService, check_scanner_dependencies
from .scanners import AVAILABLE_SCANNERS
from .utils.target_validator import TargetValidator
from .core.models import ScanTarget, ScanTargetType


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the simplified argument parser."""
    
    parser = argparse.ArgumentParser(
        description="Security Scanner - YAML Configuration Driven",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run scan with YAML configuration
  security-scanner scan-request.yaml
  
  # Generate templates
  security-scanner --generate-template basic-scan > basic-scan.yaml
  security-scanner --generate-template full-audit > full-audit.yaml
  security-scanner --generate-template container-scan > container.yaml
  
  # Validate configuration
  security-scanner --validate-config my-scan.yaml
  
  # Check system
  security-scanner --list-scanners
  security-scanner --check-dependencies
  
Template Types:
  basic-scan          - Basic scan with essential scanners
  full-audit          - Comprehensive security audit
  container-scan      - Container-focused scanning
  source-code-scan    - Source code SAST analysis  
  infrastructure-scan - Infrastructure as Code scanning
  secrets-scan        - Secrets detection only
  ci-cd               - CI/CD optimized scan
  development         - Fast development workflow

For more templates, see the templates/ directory.
        """
    )
    
    # Main command - YAML file (positional argument)
    parser.add_argument(
        "scan_request", 
        nargs="?",
        help="Path to YAML scan request file"
    )
    
    # Utility commands
    parser.add_argument(
        "--list-scanners",
        action="store_true",
        help="List available scanners and exit"
    )
    
    parser.add_argument(
        "--check-dependencies",
        action="store_true",
        help="Check scanner dependencies and exit"
    )
    
    parser.add_argument(
        "--validate-config",
        metavar="FILE",
        help="Validate YAML configuration file and exit"
    )
    
    parser.add_argument(
        "--generate-template",
        choices=[
            "basic-scan", "full-audit", "container-scan", 
            "source-code-scan", "infrastructure-scan", "secrets-scan",
            "ci-cd", "development"
        ],
        help="Generate YAML template for specified scan type"
    )
    
    parser.add_argument(
        "--list-templates",
        action="store_true",
        help="List available template types"
    )
    
    parser.add_argument(
        "--validate-targets",
        nargs="+",
        metavar="TARGET",
        help="Validate scan targets before running scans"
    )
    
    parser.add_argument(
        "--target-type",
        choices=["docker_image", "git_repository", "kubernetes_manifest", "terraform_code", "filesystem"],
        help="Target type for validation (auto-detected if not specified)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Security Scanner 2.0.0 (YAML-driven)"
    )
    
    return parser


def list_scanners() -> int:
    """List available scanners"""
    print("Available scanners:")
    for name in sorted(AVAILABLE_SCANNERS.keys()):
        print(f"  - {name}")
    return 0


def check_dependencies() -> int:
    """Check scanner dependencies"""
    missing = check_scanner_dependencies()
    if missing:
        print("Missing dependencies:")
        for scanner, tools in missing.items():
            print(f"  {scanner}: {', '.join(tools)}")
        return 1
    else:
        print("All scanner dependencies are available")
        return 0


def validate_config(config_path: str) -> int:
    """Validate YAML configuration file"""
    try:
        scan_request = ScanRequest.from_yaml(config_path)
        errors = scan_request.validate()
        
        if errors:
            print(f"Configuration validation failed for {config_path}:")
            for error in errors:
                print(f"  - {error}")
            return 1
        else:
            print(f"Configuration {config_path} is valid ✓")
            return 0
            
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error validating {config_path}: {e}")
        return 1


def generate_template(template_type: str) -> int:
    """Generate YAML template"""
    try:
        generator = TemplateGenerator()
        template_yaml = generator.generate_template(template_type)
        print(template_yaml)
        return 0
    except ValueError as e:
        print(f"Template generation error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error generating template: {e}", file=sys.stderr)
        return 1


def list_templates() -> int:
    """List available template types"""
    generator = TemplateGenerator()
    print("Available template types:")
    for template_type in generator.list_templates():
        print(f"  - {template_type}")
    return 0


def validate_targets(targets: list, target_type: Optional[str] = None) -> int:
    """Validate scan targets before running scans."""
    try:
        # Setup basic logging
        setup_logging()
        
        import logging
        logger = logging.getLogger(__name__)
        validator = TargetValidator(logger=logger)
        
        # Convert targets to ScanTarget objects
        scan_targets = []
        for target_path in targets:
            if target_type:
                # Use specified target type
                try:
                    scan_target_type = ScanTargetType(target_type)
                except ValueError:
                    print(f"Error: Invalid target type: {target_type}", file=sys.stderr)
                    return 1
            else:
                # Auto-detect target type
                scan_target_type = _detect_target_type(target_path)
            
            scan_targets.append(ScanTarget(
                path=target_path,
                target_type=scan_target_type
            ))
        
        print(f"🔍 Validating {len(scan_targets)} target(s)...")
        
        # Validate targets
        validation_results = validator.validate_targets(scan_targets)
        
        # Display results
        valid_count = 0
        invalid_count = 0
        
        for target in scan_targets:
            result = validation_results.get(target.path)
            if result and result.is_valid:
                valid_count += 1
                print(f"✓ {target.path} ({target.target_type.value}) - Valid")
                
                if result.warnings:
                    for warning in result.warnings:
                        print(f"  ⚠ Warning: {warning}")
            else:
                invalid_count += 1
                error_msg = result.error_message if result else "Unknown validation error"
                print(f"✗ {target.path} ({target.target_type.value}) - Invalid: {error_msg}")
        
        # Summary
        total = len(scan_targets)
        success_rate = (valid_count / total) * 100 if total > 0 else 0
        
        print(f"\n📊 Validation Summary:")
        print(f"  Total targets: {total}")
        print(f"  Valid targets: {valid_count}")
        print(f"  Invalid targets: {invalid_count}")
        print(f"  Success rate: {success_rate:.1f}%")
        
        if invalid_count > 0:
            return 1
        else:
            print("\n🎉 All targets validated successfully!")
            return 0
    
    except Exception as e:
        print(f"Error validating targets: {e}", file=sys.stderr)
        return 1


def _detect_target_type(target_path: str) -> ScanTargetType:
    """Auto-detect target type based on path characteristics."""
    from urllib.parse import urlparse
    
    # Check if it's a URL (likely Git repository)
    parsed = urlparse(target_path)
    if parsed.scheme in ('http', 'https', 'git', 'ssh'):
        return ScanTargetType.GIT_REPOSITORY
    
    # Check if it looks like a Docker image
    if ('/' in target_path or ':' in target_path) and not target_path.startswith('/') and not target_path.startswith('./'):
        # Heuristic: if it contains slashes or colons and doesn't look like a file path, assume Docker image
        if not Path(target_path).exists():
            return ScanTargetType.DOCKER_IMAGE
    
    # Check if it's a path
    path = Path(target_path)
    if path.exists():
        if path.is_file():
            # Check file extension for specific types
            suffix = path.suffix.lower()
            if suffix in ['.yaml', '.yml']:
                try:
                    content = path.read_text(encoding='utf-8', errors='ignore')
                    if 'kind:' in content or 'apiVersion:' in content:
                        return ScanTargetType.KUBERNETES_MANIFEST
                except:
                    pass
            elif suffix in ['.tf', '.tfvars', '.hcl']:
                return ScanTargetType.TERRAFORM_CODE
        
        # Default to filesystem for existing paths
        return ScanTargetType.FILESYSTEM
    
    # If path doesn't exist, try to guess from name
    if target_path.endswith(('.yaml', '.yml')) or 'k8s' in target_path.lower() or 'kubernetes' in target_path.lower():
        return ScanTargetType.KUBERNETES_MANIFEST
    elif target_path.endswith(('.tf', '.tfvars', '.hcl')) or 'terraform' in target_path.lower():
        return ScanTargetType.TERRAFORM_CODE
    elif '/' in target_path and ':' in target_path:
        return ScanTargetType.DOCKER_IMAGE
    
    # Default fallback
    return ScanTargetType.FILESYSTEM


def run_scan(scan_request_path: str) -> int:
    """Run security scan from YAML configuration"""
    try:
        # Load and validate scan request
        scan_request = ScanRequest.from_yaml(scan_request_path)
        
        # Validate configuration
        errors = scan_request.validate()
        if errors:
            print("Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            return 1
        
        # Convert to internal configuration format
        config = scan_request.to_security_scan_config()
        
        # Setup logging
        setup_logging(
            log_level=config.log_level,
            log_file=scan_request.logging.get('file'),
            enable_console=True
        )
        configure_third_party_loggers()
        
        # Create scan targets
        targets = scan_request.create_scan_targets()
        
        if not targets:
            print("No valid scan targets found in configuration")
            return 1
        
        # Generate scan ID
        scan_id = scan_request.generate_scan_id()
        
        # Print scan info
        print(f"Starting security scan: {scan_id}")
        if scan_request.scan_request.description:
            print(f"Description: {scan_request.scan_request.description}")
        
        enabled_scanners = [name for name, scanner_config in scan_request.scanners.items() 
                          if scanner_config.get('enabled', True)]
        print(f"Targets: {len(targets)}")
        print(f"Enabled scanners: {', '.join(enabled_scanners)}")
        
        # Create and run scanner service
        scanner_service = SecurityScannerService(config)
        summary = scanner_service.scan_targets(targets, scan_id)
        
        # Print summary
        print(f"\nScan completed: {scan_id}")
        print(f"Duration: {summary.duration:.2f}s")
        print(f"Total findings: {summary.total_findings}")
        
        if summary.overall_finding_counts.get("CRITICAL", 0) > 0:
            print(f"Critical findings: {summary.overall_finding_counts['CRITICAL']}")
        if summary.overall_finding_counts.get("HIGH", 0) > 0:
            print(f"High findings: {summary.overall_finding_counts['HIGH']}")
        
        print(f"Reports saved to: {config.output.base_dir}")
        
        # Exit with error code if high severity findings and fail_on_high is set
        if config.fail_on_high_severity:
            high_severity_count = (
                summary.overall_finding_counts.get("CRITICAL", 0) +
                summary.overall_finding_counts.get("HIGH", 0)
            )
            if high_severity_count > 0:
                print(f"Exiting with error code due to {high_severity_count} high/critical findings")
                return 1
        
        return 0
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1
    except SecurityScannerError as e:
        print(f"Scanner error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Scan request file not found: {scan_request_path}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    
    try:
        parser = create_parser()
        args = parser.parse_args()
        
        # Handle utility commands
        if args.list_scanners:
            return list_scanners()
        
        if args.check_dependencies:
            return check_dependencies()
        
        if args.validate_config:
            return validate_config(args.validate_config)
        
        if args.generate_template:
            return generate_template(args.generate_template)
        
        if args.list_templates:
            return list_templates()
        
        if args.validate_targets:
            return validate_targets(args.validate_targets, args.target_type)
        
        # Main scan command
        if not args.scan_request:
            parser.print_help()
            print("\nError: No scan request file provided", file=sys.stderr)
            print("\nExample usage:", file=sys.stderr)
            print("  security-scanner --generate-template basic-scan > my-scan.yaml", file=sys.stderr)
            print("  security-scanner my-scan.yaml", file=sys.stderr)
            return 1
        
        return run_scan(args.scan_request)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())