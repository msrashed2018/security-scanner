"""
Custom exceptions for the security scanner service.
"""


class SecurityScannerError(Exception):
    """Base exception for security scanner errors."""
    pass


class ScannerNotFoundError(SecurityScannerError):
    """Raised when a required security scanner tool is not found."""
    
    def __init__(self, scanner_name: str, message: str = None):
        self.scanner_name = scanner_name
        if message is None:
            message = f"Security scanner '{scanner_name}' not found. Please ensure it is installed and available in PATH."
        super().__init__(message)


class ScanTimeoutError(SecurityScannerError):
    """Raised when a scan operation times out."""
    
    def __init__(self, scanner_name: str, timeout: int, target: str = None):
        self.scanner_name = scanner_name
        self.timeout = timeout
        self.target = target
        
        message = f"Scan with '{scanner_name}' timed out after {timeout} seconds"
        if target:
            message += f" for target '{target}'"
        super().__init__(message)


class ScanExecutionError(SecurityScannerError):
    """Raised when a scan execution fails."""
    
    def __init__(self, scanner_name: str, return_code: int, stderr: str = None, target: str = None):
        self.scanner_name = scanner_name
        self.return_code = return_code
        self.stderr = stderr
        self.target = target
        
        message = f"Scan with '{scanner_name}' failed with return code {return_code}"
        if target:
            message += f" for target '{target}'"
        if stderr:
            message += f". Error: {stderr}"
        super().__init__(message)


class ConfigurationError(SecurityScannerError):
    """Raised when there's an error in configuration."""
    pass


class OutputFormatError(SecurityScannerError):
    """Raised when there's an error with output formatting."""
    pass


class TargetNotFoundError(SecurityScannerError):
    """Raised when a scan target is not found or accessible."""
    
    def __init__(self, target: str, target_type: str = None):
        self.target = target
        self.target_type = target_type
        
        message = f"Target '{target}' not found or not accessible"
        if target_type:
            message += f" (type: {target_type})"
        super().__init__(message)


class DependencyError(SecurityScannerError):
    """Raised when a required dependency is missing."""
    
    def __init__(self, dependency: str, purpose: str = None):
        self.dependency = dependency
        self.purpose = purpose
        
        message = f"Required dependency '{dependency}' is missing"
        if purpose:
            message += f" (needed for: {purpose})"
        super().__init__(message)