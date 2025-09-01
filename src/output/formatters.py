"""
Base formatter classes and factory for output generation.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Type
import logging

from ..core.models import ScanSummary
from ..core.config import OutputConfig
from ..core.exceptions import OutputFormatError


class BaseFormatter(ABC):
    """Base class for all output formatters."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"security_scanner.output.{self.__class__.__name__}")
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format name."""
        pass
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return the file extension for this format."""
        pass
    
    @abstractmethod
    def generate_report(self, summary: ScanSummary, output_config: OutputConfig) -> str:
        """
        Generate a report in this format.
        
        Args:
            summary: Scan summary to format
            output_config: Output configuration
            
        Returns:
            Path to the generated report file
        """
        pass
    
    def _create_output_directory(self, output_config: OutputConfig, scan_id: str) -> Path:
        """Create and return the output directory path."""
        output_dir = Path(output_config.base_dir) / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir
    
    def _get_output_file_path(self, output_dir: Path, scan_id: str, suffix: str = "") -> Path:
        """Get the output file path for this formatter."""
        filename = f"{scan_id}{suffix}.{self.file_extension}"
        return output_dir / filename
    
    def _write_file(self, file_path: Path, content: str) -> None:
        """Write content to file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.logger.info(f"Report written to {file_path}")
        except Exception as e:
            raise OutputFormatError(f"Failed to write {self.format_name} report to {file_path}: {e}")


class OutputFormatterFactory:
    """Factory for creating output formatters."""
    
    def __init__(self):
        self._formatters: Dict[str, Type[BaseFormatter]] = {}
        self._register_default_formatters()
    
    def _register_default_formatters(self) -> None:
        """Register default formatters."""
        from .json_formatter import JsonFormatter
        from .sarif_formatter import SarifFormatter
        from .html_formatter import HtmlFormatter
        
        self.register('json', JsonFormatter)
        self.register('sarif', SarifFormatter)
        self.register('html', HtmlFormatter)
    
    def register(self, format_name: str, formatter_class: Type[BaseFormatter]) -> None:
        """Register a formatter class."""
        self._formatters[format_name.lower()] = formatter_class
    
    def get_formatter(self, format_name: str) -> BaseFormatter:
        """Get a formatter instance by name."""
        format_name = format_name.lower()
        
        if format_name not in self._formatters:
            available = ', '.join(self._formatters.keys())
            raise OutputFormatError(f"Unknown output format: {format_name}. Available: {available}")
        
        formatter_class = self._formatters[format_name]
        return formatter_class()
    
    def list_formats(self) -> list[str]:
        """List all available format names."""
        return list(self._formatters.keys())