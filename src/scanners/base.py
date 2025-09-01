"""
Base scanner class and registry for security scanners.
"""

import subprocess
import shutil
import json
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Type
import logging

from ..core.models import ScanResult, ScanTarget, Finding, ScanStatus, SeverityLevel
from ..core.exceptions import (
    ScannerNotFoundError, ScanTimeoutError, ScanExecutionError
)
from ..core.config import ScannerConfig


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    
    This class defines the common interface that all scanner implementations
    must follow, ensuring consistency and modularity.
    """
    
    def __init__(self, config: ScannerConfig):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Scanner-specific configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"security_scanner.scanners.{self.name}")
        self._validate_dependencies()
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass
    
    @property
    @abstractmethod
    def supported_targets(self) -> List[str]:
        """Return list of supported target types."""
        pass
    
    @property
    @abstractmethod
    def required_tools(self) -> List[str]:
        """Return list of required command-line tools."""
        pass
    
    def _validate_dependencies(self) -> None:
        """Validate that required tools are available."""
        missing_tools = []
        for tool in self.required_tools:
            if not shutil.which(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            raise ScannerNotFoundError(
                self.name,
                f"Missing required tools: {', '.join(missing_tools)}"
            )
    
    def can_scan_target(self, target: ScanTarget) -> bool:
        """
        Check if this scanner can scan the given target type.
        
        Args:
            target: The scan target to check
            
        Returns:
            True if scanner supports this target type
        """
        return target.target_type.value in self.supported_targets
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """
        Perform a security scan on the target.
        
        Args:
            target: The target to scan
            
        Returns:
            ScanResult containing findings and metadata
        """
        if not self.config.enabled:
            return ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.SKIPPED,
                start_time=datetime.now()
            )
        
        if not self.can_scan_target(target):
            return ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.SKIPPED,
                start_time=datetime.now(),
                error_message=f"Target type {target.target_type.value} not supported"
            )
        
        start_time = datetime.now()
        self.logger.info(f"Starting {self.name} scan of {target.path}")
        
        try:
            result = self._execute_scan(target)
            result.start_time = start_time
            result.end_time = datetime.now()
            result.status = ScanStatus.COMPLETED
            
            self.logger.info(
                f"Completed {self.name} scan of {target.path} - "
                f"{len(result.findings)} findings in {result.duration:.2f}s"
            )
            
            return result
            
        except ScanTimeoutError as e:
            self.logger.error(f"Scan timeout: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.TIMEOUT,
                start_time=start_time,
                end_time=datetime.now(),
                error_message=str(e)
            )
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                error_message=str(e)
            )
    
    @abstractmethod
    def _execute_scan(self, target: ScanTarget) -> ScanResult:
        """
        Execute the actual scan. Must be implemented by subclasses.
        
        Args:
            target: The target to scan
            
        Returns:
            ScanResult with findings
        """
        pass
    
    def _run_command(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> subprocess.CompletedProcess:
        """
        Run a command with proper error handling and timeout.
        
        Args:
            command: Command and arguments to run
            timeout: Timeout in seconds (uses config timeout if not specified)
            cwd: Working directory
            env: Environment variables
            
        Returns:
            CompletedProcess result
            
        Raises:
            ScanTimeoutError: If command times out
            ScanExecutionError: If command fails
        """
        if timeout is None:
            timeout = self.config.timeout
        
        self.logger.debug(f"Running command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env
            )
            
            if result.returncode != 0:
                self.logger.debug(f"Command failed with return code {result.returncode}")
                self.logger.debug(f"STDERR: {result.stderr}")
                
                # Some scanners return non-zero codes even on success
                if not self._is_acceptable_return_code(result.returncode):
                    raise ScanExecutionError(
                        self.name,
                        result.returncode,
                        result.stderr
                    )
            
            return result
            
        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(self.name, timeout)
    
    def _is_acceptable_return_code(self, return_code: int) -> bool:
        """
        Check if a return code is acceptable for this scanner.
        Some scanners return non-zero codes when findings are present.
        
        Args:
            return_code: The return code to check
            
        Returns:
            True if the return code is acceptable
        """
        # By default, only 0 is acceptable
        return return_code == 0
    
    def _create_temp_file(self, content: str, suffix: str = ".tmp") -> str:
        """
        Create a temporary file with the given content.
        
        Args:
            content: Content to write to the file
            suffix: File suffix
            
        Returns:
            Path to the temporary file
        """
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=suffix,
            delete=False
        ) as f:
            f.write(content)
            return f.name
    
    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """
        Parse JSON output from scanner.
        
        Args:
            output: JSON string output
            
        Returns:
            Parsed JSON data
        """
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON output: {e}")
            self.logger.debug(f"Raw output: {output}")
            return {}
    
    def _normalize_severity(self, severity: str) -> SeverityLevel:
        """
        Normalize severity string to SeverityLevel enum.
        
        Args:
            severity: Severity string from scanner
            
        Returns:
            Normalized SeverityLevel
        """
        return SeverityLevel.from_string(severity)


class ScannerRegistry:
    """Registry for managing available scanners."""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScanner]] = {}
    
    def register(self, name: str, scanner_class: Type[BaseScanner]) -> None:
        """Register a scanner class."""
        self._scanners[name] = scanner_class
    
    def get_scanner(self, name: str, config: ScannerConfig) -> BaseScanner:
        """Get a scanner instance by name."""
        if name not in self._scanners:
            raise ValueError(f"Unknown scanner: {name}")
        
        scanner_class = self._scanners[name]
        return scanner_class(config)
    
    def list_scanners(self) -> List[str]:
        """List all registered scanner names."""
        return list(self._scanners.keys())
    
    def get_scanners_for_target(self, target: ScanTarget) -> List[str]:
        """Get list of scanner names that support the given target type."""
        compatible_scanners = []
        
        for name, scanner_class in self._scanners.items():
            # Create a temporary instance to check compatibility
            try:
                temp_config = ScannerConfig()
                scanner = scanner_class(temp_config)
                if scanner.can_scan_target(target):
                    compatible_scanners.append(name)
            except Exception:
                # Skip scanners that can't be instantiated
                continue
        
        return compatible_scanners


# Global scanner registry
scanner_registry = ScannerRegistry()