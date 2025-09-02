"""
Main security scanner service that orchestrates all individual scanners.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .core.config import SecurityScanConfig
from .core.models import ScanTarget, ScanResult, ScanSummary, ScanStatus
from .core.logging_config import get_logger, ScanProgressLogger
from .core.exceptions import SecurityScannerError, ScannerNotFoundError
from .scanners.base import scanner_registry
from .scanners import AVAILABLE_SCANNERS
from .output.formatters import OutputFormatterFactory
from .utils.target_validator import TargetValidator


class SecurityScannerService:
    """Main service for orchestrating security scans."""
    
    def __init__(self, config: SecurityScanConfig):
        """
        Initialize the scanner service.
        
        Args:
            config: Security scan configuration
        """
        self.config = config
        self.logger = get_logger(__name__)
        self.progress_logger = ScanProgressLogger(self.logger)
        
        # Initialize target validator
        self.target_validator = TargetValidator(logger=self.logger)
        
        # Register all available scanners
        self._register_scanners()
        
        # Initialize output formatter factory
        self.formatter_factory = OutputFormatterFactory()
    
    def _register_scanners(self) -> None:
        """Register all available scanners."""
        for name, scanner_class in AVAILABLE_SCANNERS.items():
            scanner_registry.register(name, scanner_class)
    
    def scan_targets(self, targets: List[ScanTarget], scan_id: Optional[str] = None) -> ScanSummary:
        """
        Scan multiple targets with enabled scanners.
        
        Args:
            targets: List of targets to scan
            scan_id: Optional scan ID (auto-generated if not provided)
            
        Returns:
            ScanSummary with all results
        """
        if scan_id is None:
            scan_id = f"scan-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        
        start_time = datetime.now()
        self.logger.info(f"Starting security scan: {scan_id}")
        self.logger.info(f"Targets: {len(targets)}, Enabled scanners: {list(self.config.get_enabled_scanners())}")
        
        # Validate targets before scanning
        self.logger.info("Validating targets before scanning...")
        validation_results = self.target_validator.validate_targets(targets)
        validation_summary = self.target_validator.get_validation_summary(validation_results)
        
        self.logger.info(f"Target validation summary: {validation_summary['valid_targets']}/{validation_summary['total_targets']} targets valid ({validation_summary['success_rate']})")
        
        # Filter out invalid targets
        valid_targets = []
        invalid_targets = []
        for target in targets:
            validation_result = validation_results.get(target.path)
            if validation_result and validation_result.is_valid:
                valid_targets.append(target)
                # Add validation metadata to target
                if validation_result.metadata:
                    target.metadata.update(validation_result.metadata)
            else:
                invalid_targets.append((target, validation_result.error_message if validation_result else "Unknown validation error"))
        
        if invalid_targets:
            self.logger.warning(f"Skipping {len(invalid_targets)} invalid targets:")
            for target, error in invalid_targets:
                self.logger.warning(f"  - {target.path}: {error}")
        
        if not valid_targets:
            raise SecurityScannerError("No valid targets to scan after validation")
        
        # Initialize scan summary with valid targets only
        summary = ScanSummary(
            scan_id=scan_id,
            start_time=start_time,
            targets=valid_targets,
            enabled_scanners=list(self.config.get_enabled_scanners())
        )
        
        # Add validation summary to metadata
        summary.metadata["validation_summary"] = validation_summary
        summary.metadata["invalid_targets"] = [
            {"path": target.path, "type": target.target_type.value, "error": error}
            for target, error in invalid_targets
        ]
        
        # Scan all valid targets
        all_results = []
        
        if self.config.parallel_scans:
            all_results = self._scan_targets_parallel(valid_targets)
        else:
            all_results = self._scan_targets_sequential(valid_targets)
        
        # Update summary
        summary.end_time = datetime.now()
        summary.results = all_results
        summary.total_findings = sum(len(result.findings) for result in all_results)
        
        # Generate output reports
        self._generate_reports(summary)
        
        self.progress_logger.scan_summary(
            len(targets),
            summary.total_findings,
            summary.duration
        )
        
        return summary
    
    def _scan_targets_parallel(self, targets: List[ScanTarget]) -> List[ScanResult]:
        """Scan targets in parallel."""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all scan jobs
            future_to_target = {}
            
            for target in targets:
                for scanner_name in self.config.get_enabled_scanners():
                    future = executor.submit(self._scan_target_with_scanner, target, scanner_name)
                    future_to_target[future] = (target, scanner_name)
            
            # Collect results as they complete
            for future in as_completed(future_to_target):
                target, scanner_name = future_to_target[future]
                try:
                    result = future.result()
                    all_results.append(result)
                except Exception as e:
                    self.logger.error(f"Failed to scan {target.path} with {scanner_name}: {e}")
                    # Create failed result
                    failed_result = ScanResult(
                        scanner_name=scanner_name,
                        target=target,
                        status=ScanStatus.FAILED,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        error_message=str(e)
                    )
                    all_results.append(failed_result)
        
        return all_results
    
    def _scan_targets_sequential(self, targets: List[ScanTarget]) -> List[ScanResult]:
        """Scan targets sequentially."""
        all_results = []
        
        for target in targets:
            self.progress_logger.start_target(target.path, target.target_type.value)
            target_start_time = datetime.now()
            target_results = []
            
            for scanner_name in self.config.get_enabled_scanners():
                try:
                    result = self._scan_target_with_scanner(target, scanner_name)
                    target_results.append(result)
                    all_results.append(result)
                except Exception as e:
                    self.logger.error(f"Failed to scan {target.path} with {scanner_name}: {e}")
                    failed_result = ScanResult(
                        scanner_name=scanner_name,
                        target=target,
                        status=ScanStatus.FAILED,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        error_message=str(e)
                    )
                    target_results.append(failed_result)
                    all_results.append(failed_result)
            
            # Log target completion
            target_duration = (datetime.now() - target_start_time).total_seconds()
            total_findings = sum(len(r.findings) for r in target_results)
            self.progress_logger.target_completed(target.path, total_findings, target_duration)
        
        return all_results
    
    def _scan_target_with_scanner(self, target: ScanTarget, scanner_name: str) -> ScanResult:
        """Scan a single target with a specific scanner."""
        
        # Get scanner configuration
        scanner_config = getattr(self.config, scanner_name)
        
        # Check if scanner is enabled
        if not scanner_config.enabled:
            return ScanResult(
                scanner_name=scanner_name,
                target=target,
                status=ScanStatus.SKIPPED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message="Scanner disabled in configuration"
            )
        
        try:
            # Get scanner instance
            scanner = scanner_registry.get_scanner(scanner_name, scanner_config)
            
            # Check if scanner supports this target type
            if not scanner.can_scan_target(target):
                return ScanResult(
                    scanner_name=scanner_name,
                    target=target,
                    status=ScanStatus.SKIPPED,
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    error_message=f"Target type {target.target_type.value} not supported"
                )
            
            self.progress_logger.start_scanner(scanner_name)
            
            # Execute scan
            result = scanner.scan(target)
            
            # Log completion
            if result.status == ScanStatus.COMPLETED:
                self.progress_logger.scanner_completed(
                    scanner_name,
                    len(result.findings),
                    result.duration or 0
                )
            elif result.status == ScanStatus.FAILED:
                self.progress_logger.scanner_failed(scanner_name, result.error_message or "Unknown error")
            elif result.status == ScanStatus.SKIPPED:
                self.progress_logger.scanner_skipped(scanner_name, result.error_message or "Unknown reason")
            
            return result
            
        except ScannerNotFoundError as e:
            self.logger.warning(f"Scanner {scanner_name} not available: {e}")
            return ScanResult(
                scanner_name=scanner_name,
                target=target,
                status=ScanStatus.SKIPPED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=str(e)
            )
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {target.path} with {scanner_name}: {e}")
            return ScanResult(
                scanner_name=scanner_name,
                target=target,
                status=ScanStatus.FAILED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=str(e)
            )
    
    def _generate_reports(self, summary: ScanSummary) -> None:
        """Generate output reports in configured formats."""
        
        try:
            for format_name in self.config.output.formats:
                formatter = self.formatter_factory.get_formatter(format_name)
                formatter.generate_report(summary, self.config.output)
                
                self.logger.info(f"Generated {format_name.upper()} report")
        
        except Exception as e:
            self.logger.error(f"Failed to generate reports: {e}")
    
    def check_scanner_availability(self) -> Dict[str, bool]:
        """Check which scanners are available."""
        availability = {}
        
        for scanner_name in AVAILABLE_SCANNERS.keys():
            try:
                scanner_config = getattr(self.config, scanner_name)
                scanner = scanner_registry.get_scanner(scanner_name, scanner_config)
                availability[scanner_name] = True
            except ScannerNotFoundError:
                availability[scanner_name] = False
            except Exception:
                availability[scanner_name] = False
        
        return availability


def check_scanner_dependencies() -> Dict[str, List[str]]:
    """
    Check scanner dependencies and return missing tools.
    
    Returns:
        Dictionary mapping scanner names to lists of missing tools
    """
    missing_dependencies = {}
    
    for scanner_name, scanner_class in AVAILABLE_SCANNERS.items():
        try:
            # Create temporary scanner instance to check dependencies
            from .core.config import ScannerConfig
            temp_config = ScannerConfig()
            scanner_class(temp_config)
        except ScannerNotFoundError as e:
            # Extract missing tools from error message
            missing_tools = []
            if hasattr(scanner_class, 'required_tools'):
                # Create instance without validation to get required tools
                import shutil
                for tool in scanner_class.required_tools.fget(None):
                    if not shutil.which(tool):
                        missing_tools.append(tool)
            
            if missing_tools:
                missing_dependencies[scanner_name] = missing_tools
        except Exception:
            # Skip scanners that can't be instantiated for other reasons
            continue
    
    return missing_dependencies