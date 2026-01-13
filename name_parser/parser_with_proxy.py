"""
Proxy-enabled implementation of the dork parser.
Supports HTTP, SOCKS5, and custom proxy configurations.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, List, Tuple
import logging
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProxyType(Enum):
    """Supported proxy types."""
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"


class ProxyConfig:
    """Proxy configuration manager."""
    
    def __init__(
        self,
        proxy_type: ProxyType = ProxyType.HTTP,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize proxy configuration.
        
        Args:
            proxy_type: Type of proxy (HTTP, HTTPS, SOCKS5)
            host: Proxy server hostname or IP address
            port: Proxy server port
            username: Optional proxy authentication username
            password: Optional proxy authentication password
            timeout: Request timeout in seconds
        """
        self.proxy_type = proxy_type
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        
    def get_proxy_url(self) -> Optional[str]:
        """
        Generate proxy URL from configuration.
        
        Returns:
            Proxy URL string or None if configuration is incomplete
        """
        if not self.host or not self.port:
            return None
            
        if self.username and self.password:
            return f"{self.proxy_type.value}://{self.username}:{self.password}@{self.host}:{self.port}"
        
        return f"{self.proxy_type.value}://{self.host}:{self.port}"
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """
        Get proxy dictionary for requests library.
        
        Returns:
            Dictionary with 'http' and 'https' keys or None
        """
        proxy_url = self.get_proxy_url()
        if not proxy_url:
            return None
        
        return {
            "http": proxy_url,
            "https": proxy_url,
        }


class DorkParserWithProxy:
    """Dork parser with proxy support for HTTP, SOCKS5, and custom proxies."""
    
    def __init__(
        self,
        proxy_config: Optional[ProxyConfig] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        """
        Initialize the dork parser with proxy support.
        
        Args:
            proxy_config: ProxyConfig instance for proxy settings
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retries
        """
        self.proxy_config = proxy_config
        self.session = self._create_session(max_retries, backoff_factor)
        
    def _create_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        """
        Create a requests session with retry strategy and proxy support.
        
        Args:
            max_retries: Maximum number of retries
            backoff_factor: Backoff factor for exponential retry
            
        Returns:
            Configured requests.Session instance
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        
        # Apply retry strategy to both HTTP and HTTPS
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set proxy if configured
        if self.proxy_config:
            proxy_dict = self.proxy_config.get_proxy_dict()
            if proxy_dict:
                session.proxies.update(proxy_dict)
                logger.info(f"Proxy configured: {self.proxy_config.host}:{self.proxy_config.port}")
        
        return session
    
    def fetch_dork_results(
        self,
        dork_query: str,
        search_engine: str = "google",
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """
        Fetch dork search results using configured proxy.
        
        Args:
            dork_query: The dork query string
            search_engine: Search engine to use (default: google)
            headers: Optional custom headers
            
        Returns:
            Response content as string or None if request fails
        """
        if not headers:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        
        url = self._build_search_url(dork_query, search_engine)
        
        try:
            timeout = self.proxy_config.timeout if self.proxy_config else 30
            response = self.session.get(
                url,
                headers=headers,
                timeout=timeout,
            )
            response.raise_for_status()
            logger.info(f"Successfully fetched results for dork: {dork_query}")
            return response.text
            
        except requests.exceptions.ProxyError as e:
            logger.error(f"Proxy error: {e}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"Request timeout: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def parse_dork_results(
        self,
        html_content: str,
        parser_type: str = "simple",
    ) -> List[Dict[str, str]]:
        """
        Parse dork search results from HTML content.
        
        Args:
            html_content: HTML content to parse
            parser_type: Type of parser to use (simple, advanced)
            
        Returns:
            List of parsed results as dictionaries
        """
        results = []
        
        if parser_type == "simple":
            results = self._simple_parse(html_content)
        elif parser_type == "advanced":
            results = self._advanced_parse(html_content)
        else:
            logger.warning(f"Unknown parser type: {parser_type}")
        
        return results
    
    def _simple_parse(self, html_content: str) -> List[Dict[str, str]]:
        """
        Simple HTML parsing implementation.
        
        Args:
            html_content: HTML content to parse
            
        Returns:
            List of parsed results
        """
        # Placeholder for simple parsing logic
        logger.info("Performing simple parse")
        return []
    
    def _advanced_parse(self, html_content: str) -> List[Dict[str, str]]:
        """
        Advanced HTML parsing implementation.
        
        Args:
            html_content: HTML content to parse
            
        Returns:
            List of parsed results
        """
        # Placeholder for advanced parsing logic
        logger.info("Performing advanced parse")
        return []
    
    def _build_search_url(self, dork_query: str, search_engine: str) -> str:
        """
        Build search engine URL from dork query.
        
        Args:
            dork_query: The dork query string
            search_engine: Search engine identifier
            
        Returns:
            Full search URL
        """
        if search_engine.lower() == "google":
            return f"https://www.google.com/search?q={dork_query}"
        elif search_engine.lower() == "bing":
            return f"https://www.bing.com/search?q={dork_query}"
        else:
            # Default to Google
            return f"https://www.google.com/search?q={dork_query}"
    
    def fetch_and_parse(
        self,
        dork_query: str,
        search_engine: str = "google",
        parser_type: str = "simple",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, str]]:
        """
        Fetch dork results and parse them in one operation.
        
        Args:
            dork_query: The dork query string
            search_engine: Search engine to use
            parser_type: Type of parser to use
            headers: Optional custom headers
            
        Returns:
            List of parsed results
        """
        html_content = self.fetch_dork_results(dork_query, search_engine, headers)
        
        if not html_content:
            logger.warning(f"Failed to fetch results for dork: {dork_query}")
            return []
        
        return self.parse_dork_results(html_content, parser_type)
    
    def update_proxy(self, proxy_config: Optional[ProxyConfig]) -> None:
        """
        Update proxy configuration at runtime.
        
        Args:
            proxy_config: New proxy configuration or None to disable proxy
        """
        self.proxy_config = proxy_config
        self.session = self._create_session(max_retries=3, backoff_factor=0.5)
        logger.info("Proxy configuration updated")
    
    def close(self) -> None:
        """Close the session and cleanup resources."""
        self.session.close()
        logger.info("Parser session closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Example usage functions
def example_http_proxy():
    """Example: Using HTTP proxy."""
    proxy_config = ProxyConfig(
        proxy_type=ProxyType.HTTP,
        host="proxy.example.com",
        port=8080,
        username="user",
        password="pass",
    )
    
    with DorkParserWithProxy(proxy_config) as parser:
        results = parser.fetch_and_parse("inurl:admin filetype:php")
        for result in results:
            print(result)


def example_socks5_proxy():
    """Example: Using SOCKS5 proxy."""
    proxy_config = ProxyConfig(
        proxy_type=ProxyType.SOCKS5,
        host="localhost",
        port=1080,
    )
    
    with DorkParserWithProxy(proxy_config) as parser:
        results = parser.fetch_and_parse("site:example.com", search_engine="bing")
        for result in results:
            print(result)


def example_no_proxy():
    """Example: Without proxy."""
    with DorkParserWithProxy() as parser:
        results = parser.fetch_and_parse("intitle:index.of")
        for result in results:
            print(result)


if __name__ == "__main__":
    # Test the parser with examples
    print("Proxy-enabled Dork Parser initialized successfully")
