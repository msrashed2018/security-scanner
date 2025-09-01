"""
Main entry point for the security scanner service.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())