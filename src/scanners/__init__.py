"""
Security scanner modules.

This package contains individual scanner implementations for various security tools.
Each scanner follows a common interface for consistency and modularity.
"""

from .base import BaseScanner, ScannerRegistry
from .trivy import TrivyScanner
from .grype import GrypeScanner
from .syft import SyftScanner
from .dockle import DockleScanner
from .hadolint import HadolintScanner
from .checkov import CheckovScanner
# from .kics import KicsScanner  # KICS removed due to unreliable installation
from .conftest import ConftestScanner
from .trufflehog import TruffleHogScanner
from .gitleaks import GitLeaksScanner
from .semgrep import SemgrepScanner

# Register all scanners
AVAILABLE_SCANNERS = {
    'trivy': TrivyScanner,
    'grype': GrypeScanner,
    'syft': SyftScanner,
    'dockle': DockleScanner,
    'hadolint': HadolintScanner,
    'checkov': CheckovScanner,
    # 'kics': KicsScanner,  # KICS removed due to unreliable installation
    'conftest': ConftestScanner,
    'trufflehog': TruffleHogScanner,
    'gitleaks': GitLeaksScanner,
    'semgrep': SemgrepScanner
}

__all__ = [
    'BaseScanner',
    'ScannerRegistry',
    'TrivyScanner',
    'GrypeScanner',
    'SyftScanner',
    'DockleScanner',
    'HadolintScanner',
    'CheckovScanner',
    # 'KicsScanner',  # KICS removed due to unreliable installation
    'ConftestScanner',
    'TruffleHogScanner',
    'GitLeaksScanner',
    'SemgrepScanner',
    'AVAILABLE_SCANNERS'
]