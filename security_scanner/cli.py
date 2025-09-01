"""
Command-line interface for the security scanner service.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import List, Optional
import uuid
from datetime import datetime

from .core.config import SecurityScanConfig, ScannerConfig, get_default_config
from .core.logging_config import setup_logging, configure_third_party_loggers
from .core.models import ScanTarget, ScanTargetType
from .core.exceptions import SecurityScannerError
from .scanner_service import SecurityScannerService


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    
    parser = argparse.ArgumentParser(
        description="Comprehensive security scanning service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan Docker images
  security-scanner --docker-image nginx:latest ubuntu:20.04
  
  # Scan Git repository
  security-scanner --git-repo /path/to/repo
  
  # Scan with specific tools only
  security-scanner --docker-image nginx:latest --enable-scanner trivy grype
  
  # Disable specific tools
  security-scanner --docker-image nginx:latest --disable-scanner checkov
  
  # Custom output directory and formats
  security-scanner --docker-image nginx:latest --output-dir ./my-reports --format json sarif
  
  # Use configuration file
  security-scanner --config config.yaml
  
  # Scan Kubernetes manifests
  security-scanner --k8s-manifest deployment.yaml service.yaml
  
  # Scan Terraform code
  security-scanner --terraform-code ./terraform/
        """
    )
    
    # Input targets
    target_group = parser.add_argument_group("Scan Targets")
    target_group.add_argument(
        "--docker-image", "-i",
        action="append",
        dest="docker_images",
        help="Docker image to scan (can be specified multiple times)"
    )
    target_group.add_argument(
        "--git-repo", "-r",
        action="append", 
        dest="git_repositories",
        help="Git repository path to scan (can be specified multiple times)"
    )
    target_group.add_argument(
        "--k8s-manifest", "-k",
        action="append",
        dest="kubernetes_manifests", 
        help="Kubernetes manifest file/directory to scan (can be specified multiple times)"
    )
    target_group.add_argument(
        "--terraform-code", "-t",
        action="append",
        dest="terraform_code",
        help="Terraform code directory to scan (can be specified multiple times)"
    )
    target_group.add_argument(
        "--filesystem", "-f",
        action="append",
        dest="filesystem_paths",
        help="Filesystem path to scan (can be specified multiple times)"
    )
    
    # Scanner control
    scanner_group = parser.add_argument_group("Scanner Control")
    scanner_group.add_argument(
        "--enable-scanner",
        action="append",
        dest="enabled_scanners",
        choices=["trivy", "grype", "syft", "dockle", "hadolint", "checkov",
                "conftest", "trufflehog", "gitleaks", "semgrep"],
        help="Enable specific scanners (can be specified multiple times)"
    )
    scanner_group.add_argument(
        "--disable-scanner",
        action="append", 
        dest="disabled_scanners",
        choices=["trivy", "grype", "syft", "dockle", "hadolint", "checkov",
                "conftest", "trufflehog", "gitleaks", "semgrep"],
        help="Disable specific scanners (can be specified multiple times)"
    )
    scanner_group.add_argument(
        "--severity-threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="MEDIUM",
        help="Minimum severity level to report (default: MEDIUM)"
    )
    scanner_group.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Scanner timeout in seconds (default: use config file values)"
    )
    
    # Output configuration
    output_group = parser.add_argument_group("Output Configuration")
    output_group.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    output_group.add_argument(
        "--format",
        action="append",
        dest="output_formats",
        choices=["json", "sarif", "html", "xml"],
        help="Output format (can be specified multiple times, default: json, html)"
    )
    output_group.add_argument(
        "--no-raw-output",
        action="store_true",
        help="Don't include raw scanner output in reports"
    )
    output_group.add_argument(
        "--no-executive-summary",
        action="store_true",
        help="Don't generate executive summary"
    )
    output_group.add_argument(
        "--scan-id",
        help="Custom scan ID (default: auto-generated)"
    )
    
    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config", "-c",
        help="Configuration file path (YAML or JSON)"
    )
    config_group.add_argument(
        "--save-config",
        help="Save current configuration to file"
    )
    
    # Execution options
    exec_group = parser.add_argument_group("Execution Options")
    exec_group.add_argument(
        "--parallel",
        action="store_true",
        default=True,
        help="Run scans in parallel (default: enabled)"
    )
    exec_group.add_argument(
        "--no-parallel",
        action="store_true",
        help="Disable parallel scanning"
    )
    exec_group.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Maximum number of parallel workers (default: 4)"
    )
    exec_group.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with non-zero code if high/critical findings are found"
    )
    
    # Logging
    log_group = parser.add_argument_group("Logging")
    log_group.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    log_group.add_argument(
        "--log-file",
        help="Log file path (default: console only)"
    )
    log_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress console output (except errors)"
    )
    log_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output (DEBUG level)"
    )
    
    # Utility options
    parser.add_argument(
        "--version",
        action="version",
        version="Security Scanner 1.0.0"
    )
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
    
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate command-line arguments."""
    
    # Check that at least one target is specified
    targets_specified = any([
        args.docker_images,
        args.git_repositories, 
        args.kubernetes_manifests,
        args.terraform_code,
        args.filesystem_paths
    ])
    
    if not targets_specified and not args.config and not args.list_scanners and not args.check_dependencies:
        raise ValueError("At least one scan target must be specified")
    
    # Validate paths exist
    for path_list in [args.git_repositories, args.kubernetes_manifests, 
                     args.terraform_code, args.filesystem_paths]:
        if path_list:
            for path in path_list:
                if not Path(path).exists():
                    raise ValueError(f"Path does not exist: {path}")
    
    # Validate output formats
    if args.output_formats is None:
        args.output_formats = ["json", "html"]
    
    # Handle verbose/quiet flags
    if args.verbose:
        args.log_level = "DEBUG"
    elif args.quiet:
        args.log_level = "ERROR"


def create_config_from_args(args: argparse.Namespace) -> SecurityScanConfig:
    """Create configuration from command-line arguments."""
    
    # Start with default config or load from file
    if args.config:
        config = SecurityScanConfig.from_file(args.config)
    else:
        config = get_default_config()
    
    # Override with command-line arguments
    if args.docker_images:
        config.docker_images = args.docker_images
    if args.git_repositories:
        config.git_repositories = args.git_repositories
    if args.kubernetes_manifests:
        config.kubernetes_manifests = args.kubernetes_manifests
    if args.terraform_code:
        config.terraform_code = args.terraform_code
    
    # Handle filesystem paths
    if args.filesystem_paths:
        config.filesystem_paths = args.filesystem_paths
    
    # Scanner configuration
    if args.enabled_scanners:
        # Disable all scanners first, then enable specified ones
        for scanner_name in ["trivy", "grype", "syft", "dockle", "hadolint",
                           "checkov", "conftest", "trufflehog", "gitleaks", "semgrep"]:
            getattr(config, scanner_name).enabled = scanner_name in args.enabled_scanners
    
    if args.disabled_scanners:
        for scanner_name in args.disabled_scanners:
            getattr(config, scanner_name).enabled = False
    
    # Apply global scanner settings
    for scanner_name in ["trivy", "grype", "syft", "dockle", "hadolint",
                        "checkov", "conftest", "trufflehog", "gitleaks", "semgrep"]:
        scanner_config = getattr(config, scanner_name)
        if args.timeout is not None:
            scanner_config.timeout = args.timeout
        scanner_config.severity_threshold = args.severity_threshold
    
    # Output configuration
    config.output.base_dir = args.output_dir
    config.output.formats = args.output_formats
    config.output.include_raw = not args.no_raw_output
    config.output.generate_executive_summary = not args.no_executive_summary
    
    # Execution options
    config.parallel_scans = args.parallel and not args.no_parallel
    config.max_workers = args.max_workers
    config.fail_on_high_severity = args.fail_on_high
    config.log_level = args.log_level
    
    return config


def create_scan_targets(config: SecurityScanConfig) -> List[ScanTarget]:
    """Create scan targets from configuration."""
    targets = []
    
    # Docker images
    for image in config.docker_images:
        targets.append(ScanTarget(
            path=image,
            target_type=ScanTargetType.DOCKER_IMAGE,
            name=image.split('/')[-1].split(':')[0]
        ))
    
    # Git repositories
    for repo in config.git_repositories:
        targets.append(ScanTarget(
            path=repo,
            target_type=ScanTargetType.GIT_REPOSITORY,
            name=Path(repo).name
        ))
    
    # Kubernetes manifests
    for manifest in config.kubernetes_manifests:
        targets.append(ScanTarget(
            path=manifest,
            target_type=ScanTargetType.KUBERNETES_MANIFEST,
            name=Path(manifest).name
        ))
    
    # Terraform code
    for terraform in config.terraform_code:
        targets.append(ScanTarget(
            path=terraform,
            target_type=ScanTargetType.TERRAFORM_CODE,
            name=Path(terraform).name
        ))
    
    # Filesystem paths
    for filesystem_path in config.filesystem_paths:
        targets.append(ScanTarget(
            path=filesystem_path,
            target_type=ScanTargetType.FILESYSTEM,
            name=Path(filesystem_path).name
        ))
    
    return targets


def main() -> int:
    """Main entry point for the CLI."""
    
    try:
        parser = create_parser()
        args = parser.parse_args()
        
        # Handle utility options
        if args.list_scanners:
            from .scanners import AVAILABLE_SCANNERS
            print("Available scanners:")
            for name in sorted(AVAILABLE_SCANNERS.keys()):
                print(f"  - {name}")
            return 0
        
        if args.check_dependencies:
            from .scanner_service import check_scanner_dependencies
            missing = check_scanner_dependencies()
            if missing:
                print("Missing dependencies:")
                for scanner, tools in missing.items():
                    print(f"  {scanner}: {', '.join(tools)}")
                return 1
            else:
                print("All scanner dependencies are available")
                return 0
        
        # Validate arguments
        validate_args(args)
        
        # Create configuration
        config = create_config_from_args(args)
        
        # Save configuration if requested
        if args.save_config:
            config.save_to_file(args.save_config)
            print(f"Configuration saved to {args.save_config}")
            return 0
        
        # Setup logging
        setup_logging(
            log_level=config.log_level,
            log_file=args.log_file,
            enable_console=not args.quiet
        )
        configure_third_party_loggers()
        
        # Create scan targets
        targets = create_scan_targets(config)
        
        if not targets:
            print("No valid scan targets found")
            return 1
        
        # Generate scan ID
        scan_id = args.scan_id or f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:8]}"
        
        # Create and run scanner service
        scanner_service = SecurityScannerService(config)
        summary = scanner_service.scan_targets(targets, scan_id)
        
        # Print summary
        print(f"\nScan completed: {scan_id}")
        print(f"Targets scanned: {len(targets)}")
        print(f"Total findings: {summary.total_findings}")
        print(f"Duration: {summary.duration:.2f}s")
        
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
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 130
    except SecurityScannerError as e:
        print(f"Scanner error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())