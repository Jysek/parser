"""
Comprehensive Dork Parser Implementation

A robust and feature-rich parser for analyzing, parsing, and processing search engine dorks.
Supports multiple dork types including Google dorking, Shodan queries, and custom search operators.

Author: Jysek
Date: 2026-01-13
Version: 1.0.0
"""

import re
import json
import hashlib
import logging
from typing import Dict, List, Tuple, Set, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from datetime import datetime
from urllib.parse import quote, unquote, urlencode
import unicodedata


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DorkType(Enum):
    """Enumeration of supported dork types"""
    GOOGLE = "google"
    SHODAN = "shodan"
    CENSYS = "censys"
    ZOOMEYE = "zoomeye"
    BING = "bing"
    BAIDU = "baidu"
    DUCKDUCKGO = "duckduckgo"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class OperatorType(Enum):
    """Enumeration of operator types"""
    INCLUDE = "include"
    EXCLUDE = "exclude"
    EXACT = "exact"
    RANGE = "range"
    BOOLEAN = "boolean"
    FUZZY = "fuzzy"
    CONDITIONAL = "conditional"
    MODIFIER = "modifier"


class SeverityLevel(Enum):
    """Severity levels for dork analysis"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Token:
    """Represents a single token in a dork query"""
    type: str
    value: str
    position: int
    length: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"Token({self.type}, '{self.value}' @{self.position})"


@dataclass
class ParsedOperator:
    """Represents a parsed operator from a dork query"""
    name: str
    value: str
    operator_type: OperatorType
    is_negated: bool = False
    raw_syntax: str = ""
    parameter_type: Optional[str] = None
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert operator to dictionary"""
        return {
            "name": self.name,
            "value": self.value,
            "type": self.operator_type.value,
            "negated": self.is_negated,
            "syntax": self.raw_syntax,
            "parameter_type": self.parameter_type,
            "valid": self.is_valid,
            "error": self.error_message
        }


@dataclass
class DorkAnalysis:
    """Comprehensive analysis results of a dork query"""
    original_query: str
    dork_type: DorkType
    operators: List[ParsedOperator] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    tokens: List[Token] = field(default_factory=list)
    potential_risks: List[Dict[str, Any]] = field(default_factory=list)
    estimated_results: Optional[int] = None
    query_complexity: int = 0
    has_errors: bool = False
    error_messages: List[str] = field(default_factory=list)
    optimization_suggestions: List[str] = field(default_factory=list)
    parsed_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary"""
        return {
            "original_query": self.original_query,
            "dork_type": self.dork_type.value,
            "operators": [op.to_dict() for op in self.operators],
            "keywords": self.keywords,
            "tokens_count": len(self.tokens),
            "potential_risks": self.potential_risks,
            "estimated_results": self.estimated_results,
            "complexity": self.query_complexity,
            "has_errors": self.has_errors,
            "errors": self.error_messages,
            "suggestions": self.optimization_suggestions,
            "timestamp": self.parsed_timestamp
        }

    def to_json(self, pretty: bool = True) -> str:
        """Convert analysis to JSON string"""
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict())


class DorkOperatorRegistry:
    """Registry for all supported dork operators across platforms"""

    # Google Search Operators
    GOOGLE_OPERATORS = {
        "site": {"description": "Search within a specific site", "type": OperatorType.INCLUDE},
        "inurl": {"description": "Search for URL containing keyword", "type": OperatorType.INCLUDE},
        "intitle": {"description": "Search for keyword in title", "type": OperatorType.INCLUDE},
        "intext": {"description": "Search for keyword in page text", "type": OperatorType.INCLUDE},
        "inanchor": {"description": "Search for keyword in anchor text", "type": OperatorType.INCLUDE},
        "filetype": {"description": "Search for specific file type", "type": OperatorType.INCLUDE},
        "cache": {"description": "Show cached version of page", "type": OperatorType.MODIFIER},
        "related": {"description": "Find similar pages", "type": OperatorType.MODIFIER},
        "info": {"description": "Get information about page", "type": OperatorType.MODIFIER},
        "link": {"description": "Find pages linking to URL", "type": OperatorType.INCLUDE},
        "define": {"description": "Get definition of word", "type": OperatorType.MODIFIER},
        "daterange": {"description": "Search within date range", "type": OperatorType.RANGE},
        "allintext": {"description": "All words in page text", "type": OperatorType.INCLUDE},
        "allintitle": {"description": "All words in title", "type": OperatorType.INCLUDE},
        "allinurl": {"description": "All words in URL", "type": OperatorType.INCLUDE},
        "author": {"description": "Search by author", "type": OperatorType.INCLUDE},
        "source": {"description": "Search specific news source", "type": OperatorType.INCLUDE},
    }

    # Shodan Operators
    SHODAN_OPERATORS = {
        "hostname": {"description": "Search by hostname", "type": OperatorType.INCLUDE},
        "port": {"description": "Filter by port number", "type": OperatorType.INCLUDE},
        "country": {"description": "Filter by country code", "type": OperatorType.INCLUDE},
        "city": {"description": "Filter by city", "type": OperatorType.INCLUDE},
        "org": {"description": "Filter by organization", "type": OperatorType.INCLUDE},
        "asn": {"description": "Filter by ASN", "type": OperatorType.INCLUDE},
        "product": {"description": "Filter by product", "type": OperatorType.INCLUDE},
        "version": {"description": "Filter by version", "type": OperatorType.INCLUDE},
        "os": {"description": "Filter by operating system", "type": OperatorType.INCLUDE},
        "http.status": {"description": "Filter by HTTP status", "type": OperatorType.INCLUDE},
        "http.title": {"description": "Filter by HTTP title", "type": OperatorType.INCLUDE},
        "ssl.cert.subject.cn": {"description": "Filter by SSL certificate CN", "type": OperatorType.INCLUDE},
        "has_ipv6": {"description": "Filter devices with IPv6", "type": OperatorType.BOOLEAN},
        "has_screenshot": {"description": "Filter devices with screenshot", "type": OperatorType.BOOLEAN},
        "vuln": {"description": "Filter by vulnerability", "type": OperatorType.INCLUDE},
    }

    # Censys Operators
    CENSYS_OPERATORS = {
        "location": {"description": "Filter by location", "type": OperatorType.INCLUDE},
        "service": {"description": "Filter by service", "type": OperatorType.INCLUDE},
        "protocol": {"description": "Filter by protocol", "type": OperatorType.INCLUDE},
        "autonomous_system": {"description": "Filter by AS", "type": OperatorType.INCLUDE},
        "ip": {"description": "Search by IP address", "type": OperatorType.INCLUDE},
        "certificate": {"description": "Search by certificate", "type": OperatorType.INCLUDE},
    }

    # ZoomEye Operators
    ZOOMEYE_OPERATORS = {
        "app": {"description": "Filter by application", "type": OperatorType.INCLUDE},
        "ver": {"description": "Filter by version", "type": OperatorType.INCLUDE},
        "device": {"description": "Filter by device type", "type": OperatorType.INCLUDE},
        "os": {"description": "Filter by OS", "type": OperatorType.INCLUDE},
        "country": {"description": "Filter by country", "type": OperatorType.INCLUDE},
        "city": {"description": "Filter by city", "type": OperatorType.INCLUDE},
    }

    def __init__(self):
        """Initialize operator registry"""
        self.registry: Dict[str, Dict[str, Any]] = {
            DorkType.GOOGLE.value: self.GOOGLE_OPERATORS,
            DorkType.SHODAN.value: self.SHODAN_OPERATORS,
            DorkType.CENSYS.value: self.CENSYS_OPERATORS,
            DorkType.ZOOMEYE.value: self.ZOOMEYE_OPERATORS,
        }

    def get_operator_info(self, operator_name: str, platform: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get information about an operator"""
        if platform:
            platform_ops = self.registry.get(platform, {})
            return platform_ops.get(operator_name)

        # Search across all platforms
        for platform_ops in self.registry.values():
            if operator_name in platform_ops:
                return platform_ops[operator_name]
        return None

    def is_valid_operator(self, operator_name: str, platform: Optional[str] = None) -> bool:
        """Check if an operator is valid"""
        return self.get_operator_info(operator_name, platform) is not None


class DorkLexer:
    """Lexical analyzer for dork queries"""

    # Token patterns
    TOKEN_PATTERNS = {
        'OPERATOR': r'([a-zA-Z_][a-zA-Z0-9_-]*):',
        'QUOTED_STRING': r'"[^"]*"|\'[^\']*\'',
        'RANGE': r'\[.*?\.\..*?\]',
        'RANGE_PARENTHESES': r'\(.*?\.\...*?\)',
        'BOOLEAN_AND': r'(\s+AND\s+|\s+&&\s+)',
        'BOOLEAN_OR': r'(\s+OR\s+|\s+\|\|\s+)',
        'BOOLEAN_NOT': r'(^|\s)(NOT\s+|-|\!)',
        'WILDCARD': r'\*',
        'WORD': r'[a-zA-Z0-9._\-\~\+\/@#$%&=]+',
        'WHITESPACE': r'\s+',
        'SPECIAL': r'[(){}\[\]<>]',
    }

    def __init__(self):
        """Initialize lexer"""
        self.tokens: List[Token] = []
        self.position: int = 0
        self.current_char: Optional[str] = None
        self.input_text: str = ""

    def tokenize(self, query: str) -> List[Token]:
        """Tokenize a dork query"""
        self.input_text = query
        self.position = 0
        self.tokens = []

        while self.position < len(query):
            matched = False

            for token_type, pattern in self.TOKEN_PATTERNS.items():
                regex = re.compile(pattern)
                match = regex.match(query, self.position)

                if match:
                    value = match.group(0)
                    if token_type != 'WHITESPACE':
                        token = Token(
                            type=token_type,
                            value=value,
                            position=self.position,
                            length=len(value)
                        )
                        self.tokens.append(token)
                    self.position = match.end()
                    matched = True
                    break

            if not matched:
                # Handle unexpected character
                char = query[self.position]
                token = Token(
                    type='UNKNOWN',
                    value=char,
                    position=self.position,
                    length=1
                )
                self.tokens.append(token)
                self.position += 1

        return self.tokens


class DorkDetector:
    """Detects the type of dork query"""

    DETECTION_PATTERNS = {
        DorkType.GOOGLE: [
            r'site:|inurl:|intitle:|filetype:|cache:|link:|allintext:|allintitle:',
        ],
        DorkType.SHODAN: [
            r'hostname:|port:|country:|product:|version:|has_ipv6:|http\.',
        ],
        DorkType.CENSYS: [
            r'location\.|service\.|protocol\.|autonomous_system\.|certificate\.',
        ],
        DorkType.ZOOMEYE: [
            r'app:|ver:|device:|os:',
        ],
    }

    @staticmethod
    def detect(query: str) -> DorkType:
        """Detect the type of dork query"""
        query_lower = query.lower()

        for dork_type, patterns in DorkDetector.DETECTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    return dork_type

        return DorkType.UNKNOWN


class DorkParser:
    """Main parser for dork queries with comprehensive analysis"""

    def __init__(self):
        """Initialize parser"""
        self.lexer = DorkLexer()
        self.detector = DorkDetector()
        self.registry = DorkOperatorRegistry()
        self.logger = logger

    def parse(self, query: str) -> DorkAnalysis:
        """Parse a complete dork query with full analysis"""
        analysis = DorkAnalysis(
            original_query=query,
            dork_type=DorkType.UNKNOWN,
            parsed_timestamp=datetime.utcnow().isoformat()
        )

        try:
            # Detect dork type
            analysis.dork_type = self.detector.detect(query)
            self.logger.info(f"Detected dork type: {analysis.dork_type.value}")

            # Tokenize
            analysis.tokens = self.lexer.tokenize(query)
            self.logger.debug(f"Tokenized into {len(analysis.tokens)} tokens")

            # Parse operators
            analysis.operators = self._parse_operators(query, analysis.dork_type)
            self.logger.debug(f"Parsed {len(analysis.operators)} operators")

            # Extract keywords
            analysis.keywords = self._extract_keywords(query, analysis.operators)
            self.logger.debug(f"Extracted {len(analysis.keywords)} keywords")

            # Analyze complexity
            analysis.query_complexity = self._calculate_complexity(query, analysis.operators)

            # Perform security analysis
            analysis.potential_risks = self._analyze_security_risks(query, analysis)

            # Generate optimization suggestions
            analysis.optimization_suggestions = self._generate_suggestions(query, analysis)

            # Validate query
            self._validate_query(analysis)

        except Exception as e:
            self.logger.error(f"Error parsing query: {str(e)}")
            analysis.has_errors = True
            analysis.error_messages.append(str(e))

        return analysis

    def _parse_operators(self, query: str, dork_type: DorkType) -> List[ParsedOperator]:
        """Extract and parse operators from query"""
        operators: List[ParsedOperator] = []
        platform = dork_type.value if dork_type != DorkType.UNKNOWN else None

        # Pattern for operators: word:value or -word:value
        operator_pattern = r'(-?)([a-zA-Z_][a-zA-Z0-9_-]*):([^\s]+|"[^"]*"|\'[^\']*\')'
        matches = re.finditer(operator_pattern, query)

        for match in matches:
            negation_prefix = match.group(1)
            operator_name = match.group(2)
            operator_value = match.group(3).strip('\'"')

            is_negated = bool(negation_prefix)

            # Determine operator type
            operator_info = self.registry.get_operator_info(operator_name, platform)

            if operator_info:
                operator_type = operator_info["type"]
                parsed_op = ParsedOperator(
                    name=operator_name,
                    value=operator_value,
                    operator_type=operator_type,
                    is_negated=is_negated,
                    raw_syntax=match.group(0),
                    is_valid=True
                )
            else:
                parsed_op = ParsedOperator(
                    name=operator_name,
                    value=operator_value,
                    operator_type=OperatorType.CUSTOM,
                    is_negated=is_negated,
                    raw_syntax=match.group(0),
                    is_valid=False,
                    error_message=f"Unknown operator '{operator_name}' for platform {platform}"
                )

            operators.append(parsed_op)

        return operators

    def _extract_keywords(self, query: str, operators: List[ParsedOperator]) -> List[str]:
        """Extract keywords from query (excluding operators)"""
        keywords = []
        temp_query = query

        # Remove all operators from query
        for op in operators:
            temp_query = temp_query.replace(op.raw_syntax, "")

        # Remove special characters and split
        temp_query = re.sub(r'[-+\(\)]', ' ', temp_query)
        words = temp_query.split()

        # Filter out empty strings and boolean operators
        keywords = [w for w in words if w and w.upper() not in ['AND', 'OR', 'NOT']]

        return keywords

    def _calculate_complexity(self, query: str, operators: List[ParsedOperator]) -> int:
        """Calculate query complexity score"""
        complexity = 0

        # Base complexity from query length
        complexity += len(query) // 10

        # Operator count
        complexity += len(operators) * 5

        # Boolean operations
        boolean_count = len(re.findall(r'\s(AND|OR|NOT)\s', query))
        complexity += boolean_count * 3

        # Nested expressions
        nesting = max([query[:i].count('(') - query[:i].count(')') for i in range(len(query))])
        complexity += nesting * 2

        # Quoted strings
        quoted_count = len(re.findall(r'"[^"]*"', query))
        complexity += quoted_count

        return min(complexity, 100)  # Cap at 100

    def _analyze_security_risks(self, query: str, analysis: DorkAnalysis) -> List[Dict[str, Any]]:
        """Analyze potential security implications of the dork"""
        risks = []

        # Check for sensitive file types
        sensitive_extensions = ['sql', 'conf', 'cfg', 'key', 'pem', 'env', 'yml', 'yaml', 'json']
        for ext in sensitive_extensions:
            if f'filetype:{ext}' in query.lower():
                risks.append({
                    "severity": SeverityLevel.HIGH.value,
                    "description": f"Query searches for potentially sensitive files (.{ext})",
                    "recommendation": "Ensure responsible disclosure when using this query"
                })

        # Check for admin/login page searches
        if any(keyword in query.lower() for keyword in ['admin', 'login', 'panel', 'dashboard']):
            if 'inurl:' in query or 'intitle:' in query:
                risks.append({
                    "severity": SeverityLevel.MEDIUM.value,
                    "description": "Query appears to target admin/login pages",
                    "recommendation": "Only use for authorized security testing"
                })

        # Check for database-related searches
        if any(keyword in query.lower() for keyword in ['database', 'db', 'phpmyadmin', 'mysql']):
            risks.append({
                "severity": SeverityLevel.HIGH.value,
                "description": "Query targets database management systems",
                "recommendation": "Ensure proper authorization before executing"
            })

        # Check for credential-related searches
        if any(keyword in query.lower() for keyword in ['password', 'credential', 'token', 'api_key']):
            risks.append({
                "severity": SeverityLevel.CRITICAL.value,
                "description": "Query appears to search for credentials",
                "recommendation": "Subject to legal restrictions in many jurisdictions"
            })

        return risks

    def _generate_suggestions(self, query: str, analysis: DorkAnalysis) -> List[str]:
        """Generate optimization suggestions"""
        suggestions = []

        # Suggest using site: operator if not present
        if ':' not in query and analysis.dork_type == DorkType.GOOGLE:
            suggestions.append("Consider using 'site:' operator to narrow results to specific domain")

        # Suggest filetype filtering
        if 'filetype:' not in query.lower() and analysis.dork_type == DorkType.GOOGLE:
            suggestions.append("Consider using 'filetype:' to search specific file types")

        # Check for overly broad queries
        if len(analysis.keywords) > 10:
            suggestions.append("Query contains many keywords - consider narrowing scope")

        # Check for missing quotes
        if '\"' not in query and len(analysis.keywords) > 2:
            suggestions.append("Consider using quotes around multi-word phrases for more precise results")

        # Suggest using AND/OR operators
        if ' AND ' not in query and ' OR ' not in query and len(analysis.keywords) > 3:
            suggestions.append("Consider using AND/OR operators to refine search logic")

        return suggestions

    def _validate_query(self, analysis: DorkAnalysis) -> None:
        """Validate query syntax and operators"""
        # Check for unmatched quotes
        quote_count = analysis.original_query.count('"') + analysis.original_query.count("'")
        if quote_count % 2 != 0:
            analysis.has_errors = True
            analysis.error_messages.append("Unmatched quotes in query")

        # Check for unmatched parentheses
        paren_balance = analysis.original_query.count('(') - analysis.original_query.count(')')
        if paren_balance != 0:
            analysis.has_errors = True
            analysis.error_messages.append("Unmatched parentheses in query")

        # Check for invalid operators
        for op in analysis.operators:
            if not op.is_valid:
                analysis.has_errors = True

    def parse_batch(self, queries: List[str]) -> List[DorkAnalysis]:
        """Parse multiple dork queries"""
        results = []
        for query in queries:
            results.append(self.parse(query))
        return results


class DorkFormatter:
    """Format dork queries for different platforms"""

    @staticmethod
    def format_for_google(analysis: DorkAnalysis) -> str:
        """Format analysis as Google search query"""
        query = ""
        for op in analysis.operators:
            if op.operator_type == OperatorType.INCLUDE:
                prefix = "-" if op.is_negated else ""
                query += f' {prefix}{op.name}:{op.value}'
        query += " " + " ".join(analysis.keywords)
        return query.strip()

    @staticmethod
    def format_for_shodan(analysis: DorkAnalysis) -> str:
        """Format analysis as Shodan query"""
        query = ""
        for op in analysis.operators:
            if op.operator_type == OperatorType.INCLUDE:
                prefix = "-" if op.is_negated else ""
                query += f' {prefix}{op.name}:{op.value}'
        query += " " + " ".join(analysis.keywords)
        return query.strip()

    @staticmethod
    def format_for_url(query: str) -> str:
        """URL encode dork query"""
        return quote(query)

    @staticmethod
    def normalize_query(query: str) -> str:
        """Normalize dork query"""
        # Remove extra whitespace
        query = ' '.join(query.split())
        # Normalize unicode
        query = unicodedata.normalize('NFKD', query)
        return query


class DorkValidator:
    """Validate dork queries against rules"""

    VALIDATION_RULES = {
        "max_length": 2048,
        "min_length": 1,
        "allowed_special_chars": r'[-_:()"\'\[\]*&|]',
        "disallowed_patterns": [
            r'\.\.\.+',  # Multiple dots
            r'   +',     # Multiple spaces
        ]
    }

    @staticmethod
    def validate(query: str) -> Tuple[bool, List[str]]:
        """Validate a dork query"""
        errors = []

        if len(query) < DorkValidator.VALIDATION_RULES["min_length"]:
            errors.append("Query is too short")

        if len(query) > DorkValidator.VALIDATION_RULES["max_length"]:
            errors.append(f"Query exceeds maximum length of {DorkValidator.VALIDATION_RULES['max_length']}")

        for pattern in DorkValidator.VALIDATION_RULES["disallowed_patterns"]:
            if re.search(pattern, query):
                errors.append(f"Query contains disallowed pattern: {pattern}")

        return len(errors) == 0, errors


class DorkStatistics:
    """Generate statistics about dork queries"""

    def __init__(self):
        """Initialize statistics"""
        self.analyses: List[DorkAnalysis] = []

    def add_analysis(self, analysis: DorkAnalysis) -> None:
        """Add analysis to statistics"""
        self.analyses.append(analysis)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        if not self.analyses:
            return {}

        stats = {
            "total_queries": len(self.analyses),
            "total_operators": sum(len(a.operators) for a in self.analyses),
            "total_keywords": sum(len(a.keywords) for a in self.analyses),
            "dork_type_distribution": defaultdict(int),
            "operator_frequency": defaultdict(int),
            "average_complexity": 0,
            "high_risk_queries": 0,
            "queries_with_errors": 0,
        }

        complexity_sum = 0
        high_risk_count = 0
        error_count = 0

        for analysis in self.analyses:
            stats["dork_type_distribution"][analysis.dork_type.value] += 1
            complexity_sum += analysis.query_complexity

            if any(r["severity"] == SeverityLevel.CRITICAL.value for r in analysis.potential_risks):
                high_risk_count += 1

            if analysis.has_errors:
                error_count += 1

            for op in analysis.operators:
                stats["operator_frequency"][op.name] += 1

        stats["average_complexity"] = complexity_sum // len(self.analyses) if self.analyses else 0
        stats["high_risk_queries"] = high_risk_count
        stats["queries_with_errors"] = error_count
        stats["dork_type_distribution"] = dict(stats["dork_type_distribution"])
        stats["operator_frequency"] = dict(sorted(
            stats["operator_frequency"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])

        return stats


class DorkOptimizer:
    """Optimize dork queries for efficiency"""

    @staticmethod
    def remove_redundant_operators(query: str) -> str:
        """Remove redundant operators"""
        operators = re.findall(r'([a-zA-Z_][a-zA-Z0-9_-]*):([^\s]+)', query)
        seen = set()
        optimized = []

        for op_name, op_value in operators:
            key = (op_name, op_value)
            if key not in seen:
                seen.add(key)
                optimized.append(f"{op_name}:{op_value}")

        return " ".join(optimized)

    @staticmethod
    def combine_similar_operators(query: str) -> str:
        """Combine similar operators when possible"""
        # This is a simplified version - actual implementation would be more complex
        return query

    @staticmethod
    def suggest_alternative_operators(operator: str, platform: DorkType) -> List[str]:
        """Suggest alternative operators"""
        alternatives = {
            "site": ["inurl"],
            "inurl": ["site"],
            "intitle": ["allintitle"],
        }
        return alternatives.get(operator, [])


def parse_dork(query: str) -> DorkAnalysis:
    """Convenience function to parse a dork query"""
    parser = DorkParser()
    return parser.parse(query)


def parse_dorks(queries: List[str]) -> List[DorkAnalysis]:
    """Convenience function to parse multiple dork queries"""
    parser = DorkParser()
    return parser.parse_batch(queries)


def analyze_dork_security(query: str) -> List[Dict[str, Any]]:
    """Convenience function to analyze dork security risks"""
    analysis = parse_dork(query)
    return analysis.potential_risks


def optimize_dork(query: str) -> str:
    """Convenience function to optimize a dork query"""
    return DorkOptimizer.remove_redundant_operators(query)


def validate_dork(query: str) -> Tuple[bool, List[str]]:
    """Convenience function to validate a dork query"""
    return DorkValidator.validate(query)


def get_dork_statistics(queries: List[str]) -> Dict[str, Any]:
    """Convenience function to get statistics for multiple dorks"""
    stats = DorkStatistics()
    parser = DorkParser()
    for query in queries:
        analysis = parser.parse(query)
        stats.add_analysis(analysis)
    return stats.get_statistics()


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for examples
    logging.basicConfig(level=logging.DEBUG)

    # Test queries
    test_queries = [
        'site:example.com intitle:"admin panel"',
        'port:22 country:US',
        'filetype:pdf inurl:database',
        'site:github.com password OR credential',
        'inurl:phpMyAdmin intitle:"Welcome to phpMyAdmin"',
    ]

    print("=" * 80)
    print("DORK PARSER COMPREHENSIVE TEST")
    print("=" * 80)

    parser = DorkParser()

    for query in test_queries:
        print(f"\nParsing: {query}")
        print("-" * 80)
        analysis = parser.parse(query)
        print(analysis.to_json())
        print()

    print("\n" + "=" * 80)
    print("BATCH PARSING TEST")
    print("=" * 80)
    results = parser.parse_batch(test_queries)
    stats = DorkStatistics()
    for result in results:
        stats.add_analysis(result)

    print(json.dumps(stats.get_statistics(), indent=2))
