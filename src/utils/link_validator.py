"""
Link validator for security scanner HTML reports.
Validates that all HTML links point to existing files in the generated report structure.
"""

import json
from pathlib import Path
from typing import Dict, List, Set
import re
import logging

logger = logging.getLogger(__name__)


class LinkValidator:
    """Validates all links in generated HTML reports."""
    
    def __init__(self, reports_base_dir: str = "reports"):
        self.reports_base_dir = Path(reports_base_dir)
        self.broken_links = []
        self.validated_files = []
    
    def validate_all_links(self) -> Dict[str, List[str]]:
        """Validate all links in all HTML files in the reports directory."""
        self.broken_links = []
        self.validated_files = []
        
        if not self.reports_base_dir.exists():
            return {"error": ["Reports directory does not exist"]}
        
        # Find all HTML files
        html_files = list(self.reports_base_dir.rglob("*.html"))
        
        for html_file in html_files:
            self._validate_html_file(html_file)
        
        return {
            "validated_files": len(self.validated_files),
            "broken_links": self.broken_links,
            "status": "valid" if not self.broken_links else "invalid"
        }
    
    def _validate_html_file(self, html_file: Path) -> None:
        """Validate all links in a single HTML file."""
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all href links
            href_pattern = r'href=["\'](.*?)["\']'
            links = re.findall(href_pattern, content)
            
            for link in links:
                if self._is_external_link(link):
                    continue  # Skip external links
                
                if self._is_fragment_link(link):
                    continue  # Skip fragment links like #section
                
                # Resolve relative path
                target_path = self._resolve_link_path(html_file, link)
                
                if not target_path.exists():
                    self.broken_links.append({
                        "file": str(html_file.relative_to(self.reports_base_dir)),
                        "link": link,
                        "resolved_path": str(target_path),
                        "error": "Target file does not exist"
                    })
            
            self.validated_files.append(str(html_file.relative_to(self.reports_base_dir)))
            
        except Exception as e:
            self.broken_links.append({
                "file": str(html_file.relative_to(self.reports_base_dir)),
                "link": "",
                "resolved_path": "",
                "error": f"Failed to read file: {e}"
            })
    
    def _is_external_link(self, link: str) -> bool:
        """Check if link is external (http/https)."""
        return link.startswith(('http://', 'https://', '//', 'mailto:', 'tel:'))
    
    def _is_fragment_link(self, link: str) -> bool:
        """Check if link is a fragment link (#section)."""
        return link.startswith('#')
    
    def _resolve_link_path(self, html_file: Path, link: str) -> Path:
        """Resolve relative link path to absolute path."""
        if link.startswith('/'):
            # Absolute path from reports root
            return self.reports_base_dir / link.lstrip('/')
        else:
            # Relative path from current file
            return html_file.parent / link
    
    def generate_validation_report(self) -> str:
        """Generate a validation report."""
        validation_result = self.validate_all_links()
        
        if validation_result["status"] == "valid":
            report = f"""
# Link Validation Report ✅

**Status:** All links are valid!

**Summary:**
- Files validated: {validation_result['validated_files']}
- Broken links found: 0

All HTML files in the reports directory have valid internal links.
"""
        else:
            broken_count = len(validation_result['broken_links'])
            report = f"""
# Link Validation Report ❌

**Status:** Found {broken_count} broken links

**Summary:**
- Files validated: {validation_result['validated_files']}
- Broken links found: {broken_count}

## Broken Links:

"""
            for i, broken_link in enumerate(validation_result['broken_links'], 1):
                report += f"""
### {i}. {broken_link['file']}
- **Link:** `{broken_link['link']}`
- **Resolved to:** `{broken_link['resolved_path']}`
- **Error:** {broken_link['error']}
"""
        
        return report


def validate_reports(reports_dir: str = "reports") -> None:
    """Validate all links in reports directory and print results."""
    validator = LinkValidator(reports_dir)
    report = validator.generate_validation_report()
    print(report)
    
    # Also save to file
    report_file = Path(reports_dir) / "link_validation_report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\nValidation report saved to: {report_file}")


if __name__ == "__main__":
    import sys
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    validate_reports(reports_dir)