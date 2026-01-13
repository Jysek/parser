"""
Proxyless implementation of the dork parser.

This module provides a pure Python implementation of a dork parser
that doesn't use any proxy or external network services. It can parse
and validate search engine dorks locally without requiring external dependencies.
"""

import re
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum


class DorkType(Enum):
    """Enumeration of supported dork types."""
    GOOGLE = "google"
    BING = "bing"
    YAHOO = "yahoo"
    DUCK = "duckduckgo"
    GITHUB = "github"
    SHODAN = "shodan"


@dataclass
class DorkOperator:
    """Represents a single dork search operator."""
    operator: str
    value: str
    negated: bool = False


@dataclass
class ParsedDork:
    """Represents a parsed dork query."""
    original: str
    dork_type: DorkType
    operators: List[DorkOperator]
    keywords: List[str]
    raw_parts: List[str]


class DorkParser:
    """Proxyless parser for search engine dorks."""

    # Supported operators by search engine
    GOOGLE_OPERATORS = {
        'site', 'inurl', 'intitle', 'intext', 'cache', 'filetype',
        'related', 'link', 'numrange', 'daterange', 'author', 'group'
    }

    BING_OPERATORS = {
        'site', 'contains', 'inurl', 'intitle', 'language', 'ip', 'loc'
    }

    YAHOO_OPERATORS = {
        'site', 'inurl', 'intitle', 'inanchor', 'url'
    }

    GITHUB_OPERATORS = {
        'repo', 'user', 'org', 'language', 'stars', 'forks', 'followers',
        'created', 'pushed', 'is', 'filename', 'path'
    }

    SHODAN_OPERATORS = {
        'hostname', 'port', 'country', 'city', 'org', 'os', 'net', 'version',
        'product', 'title', 'http', 'ssl', 'hash', 'has_ipv6', 'asn'
    }

    # Operator patterns
    OPERATOR_PATTERN = re.compile(
        r'(-?)(\w+):(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))',
        re.IGNORECASE
    )

    def __init__(self):
        """Initialize the DorkParser."""
        self.dork_type = DorkType.GOOGLE

    def set_dork_type(self, dork_type: DorkType) -> None:
        """
        Set the dork type for parsing.

        Args:
            dork_type: The type of dork to parse.
        """
        self.dork_type = dork_type

    def parse(self, dork_query: str) -> ParsedDork:
        """
        Parse a dork query string.

        Args:
            dork_query: The dork query string to parse.

        Returns:
            A ParsedDork object containing parsed components.
        """
        operators = []
        keywords = []
        raw_parts = []

        # Clean up the query
        query = dork_query.strip()
        remaining = query

        # Extract operators
        for match in self.OPERATOR_PATTERN.finditer(query):
            negated = match.group(1) == '-'
            operator = match.group(2).lower()
            value = match.group(3) or match.group(4) or match.group(5)

            # Validate operator for this dork type
            if self._is_valid_operator(operator):
                operators.append(DorkOperator(
                    operator=operator,
                    value=value,
                    negated=negated
                ))
                raw_parts.append(match.group(0))
                remaining = remaining.replace(match.group(0), '', 1)

        # Extract remaining keywords
        keywords = [kw.strip() for kw in remaining.split() if kw.strip()]

        return ParsedDork(
            original=query,
            dork_type=self.dork_type,
            operators=operators,
            keywords=keywords,
            raw_parts=raw_parts
        )

    def _is_valid_operator(self, operator: str) -> bool:
        """
        Check if an operator is valid for the current dork type.

        Args:
            operator: The operator to validate.

        Returns:
            True if the operator is valid for the current dork type.
        """
        operator_lower = operator.lower()

        if self.dork_type == DorkType.GOOGLE:
            return operator_lower in self.GOOGLE_OPERATORS
        elif self.dork_type == DorkType.BING:
            return operator_lower in self.BING_OPERATORS
        elif self.dork_type == DorkType.YAHOO:
            return operator_lower in self.YAHOO_OPERATORS
        elif self.dork_type == DorkType.GITHUB:
            return operator_lower in self.GITHUB_OPERATORS
        elif self.dork_type == DorkType.SHODAN:
            return operator_lower in self.SHODAN_OPERATORS

        return False

    def validate(self, dork_query: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a dork query for syntax errors.

        Args:
            dork_query: The dork query to validate.

        Returns:
            A tuple of (is_valid, error_message).
        """
        try:
            # Check for unmatched quotes
            if dork_query.count('"') % 2 != 0:
                return False, "Unmatched double quotes"
            if dork_query.count("'") % 2 != 0:
                return False, "Unmatched single quotes"

            # Check for unmatched parentheses
            if dork_query.count('(') != dork_query.count(')'):
                return False, "Unmatched parentheses"

            # Parse the query
            parsed = self.parse(dork_query)

            # Validate operators
            for op in parsed.operators:
                if not op.value:
                    return False, f"Operator '{op.operator}' has no value"

            return True, None

        except Exception as e:
            return False, str(e)

    def get_supported_operators(self) -> Set[str]:
        """
        Get the list of supported operators for the current dork type.

        Returns:
            A set of supported operators.
        """
        if self.dork_type == DorkType.GOOGLE:
            return self.GOOGLE_OPERATORS.copy()
        elif self.dork_type == DorkType.BING:
            return self.BING_OPERATORS.copy()
        elif self.dork_type == DorkType.YAHOO:
            return self.YAHOO_OPERATORS.copy()
        elif self.dork_type == DorkType.GITHUB:
            return self.GITHUB_OPERATORS.copy()
        elif self.dork_type == DorkType.SHODAN:
            return self.SHODAN_OPERATORS.copy()

        return set()

    def to_query_string(self, parsed_dork: ParsedDork) -> str:
        """
        Convert a parsed dork back to a query string.

        Args:
            parsed_dork: The parsed dork to convert.

        Returns:
            A query string representation.
        """
        parts = []

        for op in parsed_dork.operators:
            negation = '-' if op.negated else ''
            # Quote value if it contains spaces
            if ' ' in op.value:
                value = f'"{op.value}"'
            else:
                value = op.value
            parts.append(f'{negation}{op.operator}:{value}')

        parts.extend(parsed_dork.keywords)
        return ' '.join(parts)

    def extract_domains(self, parsed_dork: ParsedDork) -> List[str]:
        """
        Extract domain names from a parsed dork.

        Args:
            parsed_dork: The parsed dork to extract from.

        Returns:
            A list of domain names found.
        """
        domains = []

        for op in parsed_dork.operators:
            if op.operator.lower() == 'site':
                domains.append(op.value)

        return domains

    def extract_file_types(self, parsed_dork: ParsedDork) -> List[str]:
        """
        Extract file types from a parsed dork.

        Args:
            parsed_dork: The parsed dork to extract from.

        Returns:
            A list of file types found.
        """
        file_types = []

        for op in parsed_dork.operators:
            if op.operator.lower() == 'filetype':
                file_types.append(op.value)

        return file_types


def create_parser(dork_type: DorkType = DorkType.GOOGLE) -> DorkParser:
    """
    Factory function to create a DorkParser instance.

    Args:
        dork_type: The type of dork to parse.

    Returns:
        A configured DorkParser instance.
    """
    parser = DorkParser()
    parser.set_dork_type(dork_type)
    return parser
