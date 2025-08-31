"""
Configuration settings for the HTTPS-to-HTTP proxy server
"""

import os


class ProxyConfig:
    """Configuration class for proxy settings"""
    
    def __init__(self):
        # Server settings
        self.timeout = int(os.getenv('PROXY_TIMEOUT', '30'))
        self.ignore_ssl_errors = os.getenv('PROXY_IGNORE_SSL', 'false').lower() == 'true'
        
        # User agent for outgoing requests
        self.user_agent = os.getenv('PROXY_USER_AGENT', 
                                   'Mozilla/5.0 (compatible; WAP-Proxy/1.0)')
        
        # Maximum response size (to prevent memory issues with large files)
        self.max_response_size = int(os.getenv('PROXY_MAX_RESPONSE_SIZE', '10485760'))  # 10MB
        
        # Blocked domains (for security)
        blocked_domains_str = os.getenv('PROXY_BLOCKED_DOMAINS', '')
        self.blocked_domains = [domain.strip() for domain in blocked_domains_str.split(',') if domain.strip()]
        
        # Allowed domains (if specified, only these domains will be proxied)
        allowed_domains_str = os.getenv('PROXY_ALLOWED_DOMAINS', '')
        self.allowed_domains = [domain.strip() for domain in allowed_domains_str.split(',') if domain.strip()]
        
        # WAP-specific settings
        self.simplify_html = os.getenv('PROXY_SIMPLIFY_HTML', 'false').lower() == 'true'
        self.strip_javascript = os.getenv('PROXY_STRIP_JAVASCRIPT', 'true').lower() == 'true'
        self.strip_css = os.getenv('PROXY_STRIP_CSS', 'false').lower() == 'true'
    
    def is_domain_allowed(self, domain):
        """Check if a domain is allowed to be proxied"""
        domain = domain.lower()
        
        # Check blocked domains first
        for blocked in self.blocked_domains:
            if blocked.lower() in domain:
                return False
        
        # If allowed domains are specified, check against them
        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if allowed.lower() in domain:
                    return True
            return False
        
        # If no restrictions, allow all domains except blocked ones
        return True
    
    def get_simplified_content_types(self):
        """Get content types that should be simplified for WAP browsers"""
        return [
            'text/html',
            'application/xhtml+xml',
            'text/xml',
            'application/xml'
        ]
