"""
Template loader utility for HTML templates.
Provides functionality to load and render HTML templates with variable substitution.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class TemplateLoader:
    """Loads and renders HTML templates with variable substitution."""
    
    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize the template loader.
        
        Args:
            templates_dir: Directory containing template files. 
                          Defaults to src/templates relative to this file.
        """
        if templates_dir is None:
            # Get the directory where this file is located
            current_file = Path(__file__)
            src_dir = current_file.parent.parent
            self.templates_dir = src_dir / 'templates'
        else:
            self.templates_dir = Path(templates_dir)
            
        if not self.templates_dir.exists():
            logger.warning(f"Templates directory not found: {self.templates_dir}")
            
    def load_template(self, template_name: str) -> str:
        """
        Load a template file and return its content.
        
        Args:
            template_name: Name of the template file (with or without .html extension)
            
        Returns:
            Template content as string
            
        Raises:
            FileNotFoundError: If template file doesn't exist
        """
        # Ensure .html extension if no other extension is present
        if not any(template_name.endswith(ext) for ext in ['.html', '.css', '.js']):
            template_name += '.html'
            
        template_path = self.templates_dir / template_name
        
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
            
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading template {template_path}: {e}")
            raise
            
    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Load and render a template with the provided context variables.
        
        Args:
            template_name: Name of the template file
            context: Dictionary of variables to substitute in the template
            
        Returns:
            Rendered HTML content
        """
        template_content = self.load_template(template_name)
        return self.render_string(template_content, context)
        
    def render_string(self, template_string: str, context: Dict[str, Any]) -> str:
        """
        Render a template string with the provided context variables.
        Uses simple {{ variable }} substitution.

        Args:
            template_string: Template content as string
            context: Dictionary of variables to substitute

        Returns:
            Rendered content
        """
        try:
            # Convert {{ variable }} format to {variable} format for Python's format method
            import re
            
            # Replace {{ variable }} with {variable} for format method, trimming whitespace
            formatted_template = re.sub(r'\{\{\s*([^}]+?)\s*\}\}', r'{\1}', template_string)
            
            # Handle nested dictionary access like {{ stats.total }}
            flattened_context = self._flatten_context(context)
            
            # Use format method for variable substitution with default values
            return formatted_template.format(**flattened_context)
            
        except KeyError as e:
            missing_var = str(e).strip("'")
            # Provide reasonable defaults for common template variables
            defaults = self._get_default_values()
            if missing_var in defaults:
                flattened_context[missing_var] = defaults[missing_var]
                try:
                    return formatted_template.format(**flattened_context)
                except KeyError:
                    # Still missing variables after adding defaults
                    pass
            
            logger.debug(f"Template variable '{missing_var}' not found and no default available")
            # Return template with missing variables replaced with empty or default values
            return template_string.replace(f'{{{{{missing_var}}}}}', defaults.get(missing_var, f'[{missing_var}]'))
        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            return template_string
            
    def _flatten_context(self, context: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """
        Flatten nested dictionaries for template substitution.
        Converts {'stats': {'total': 10}} to {'stats.total': 10}
        """
        flattened = {}
        
        for key, value in context.items():
            new_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                flattened.update(self._flatten_context(value, new_key))
            else:
                flattened[new_key] = value
                
        return flattened
        
    def _get_default_values(self) -> Dict[str, str]:
        """Get default values for common template variables."""
        return {
            'scan_id': 'Unknown Scan',
            'target': 'Unknown Target',
            'target_name': 'Unknown Target',
            'timestamp': 'Unknown Time',
            'start_time': 'Unknown Time',
            'scanner': 'Unknown Scanner',
            'scanner_name': 'Unknown Scanner',
            'total_findings': '0',
            'severity': 'info',
            'severity_class': 'info',
            'title': 'Security Finding',
            'location': 'N/A',
            'year': '2025'
        }
        
    def list_templates(self) -> list:
        """
        List all available template files.
        
        Returns:
            List of template file names
        """
        if not self.templates_dir.exists():
            return []
            
        return [f.name for f in self.templates_dir.glob('*.html')]


# Global template loader instance
template_loader = TemplateLoader()