"""
Name Parser Package

A package for parsing and processing names with support for various formats and languages.
"""

# Import main classes for package-level access
try:
    from name_parser.parser import NameParser
    from name_parser.models import Name, NamePart
except ImportError:
    # Allow package initialization even if modules aren't fully set up yet
    pass

__version__ = "0.1.0"
__author__ = "Jysek"

# Define public API
__all__ = [
    "NameParser",
    "Name",
    "NamePart",
]
