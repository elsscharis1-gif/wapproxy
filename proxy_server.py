#!/usr/bin/env python3
"""
HTTPS-to-HTTP Proxy Server for Legacy WAP Browsers
Converts HTTP requests from old mobile devices to HTTPS requests for modern websites
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import urllib.error
import ssl
import logging
import argparse
import sys
import socket
from http import HTTPStatus
import gzip
import io
import re
from config import ProxyConfig


class HTTPSToHTTPProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that proxies requests to HTTPS endpoints"""
    
    def __init__(self, *args, **kwargs):
        self.config = ProxyConfig()
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logging configuration"""
        logging.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        self._handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self._handle_request('POST')
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self._handle_request('HEAD')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self._handle_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self._handle_request('DELETE')
    
    def _handle_request(self, method):
        """Generic request handler that proxies to HTTPS"""
        try:
            # Parse the request URL
            parsed_url = urllib.parse.urlparse(self.path)
            
            # Check if this is a self-referencing request to prevent infinite loops
            host_header = self.headers.get('Host', '')
            server_ports = [':80', ':5000', ':8000']
            if any(port in host_header for port in server_ports) or '127.0.0.1' in host_header or 'localhost' in host_header:
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Cannot proxy to self - please specify a target website")
                return
            
            # If no scheme is provided, assume we're proxying to HTTPS
            if not parsed_url.scheme:
                if parsed_url.path.startswith('/http://'):
                    # Handle explicit HTTP URLs (remove leading slash)
                    target_url = self.path[1:]
                elif parsed_url.path.startswith('/https://'):
                    # Handle explicit HTTPS URLs (remove leading slash)
                    target_url = self.path[1:]
                else:
                    # Default behavior: convert to HTTPS
                    # Extract host from Host header if available, but prevent self-reference
                    host = self.headers.get('Host', 'www.google.com')
                    server_ports = [':80', ':5000', ':8000']
                    if any(port in host for port in server_ports) or '127.0.0.1' in host or 'localhost' in host:
                        host = 'www.google.com'
                    target_url = f"https://{host}{self.path}"
            else:
                target_url = self.path
            
            logging.info(f"Proxying {method} request to: {target_url}")
            
            # Store current target host for link translation
            try:
                parsed_target = urllib.parse.urlparse(target_url)
                self._current_target_host = parsed_target.netloc
            except:
                self._current_target_host = 'www.google.com'
            
            # Prepare request data
            request_data = None
            if method in ['POST', 'PUT']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    request_data = self.rfile.read(content_length)
            
            # Create the proxied request
            response = self._make_https_request(target_url, method, request_data)
            
            if response:
                self._send_response(response)
            else:
                self._send_error_response(HTTPStatus.BAD_GATEWAY, "Failed to connect to target server")
                
        except Exception as e:
            logging.error(f"Error handling request: {str(e)}")
            self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
    
    def _make_https_request(self, url, method, data=None):
        """Make HTTPS request to target server"""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            
            # For legacy compatibility, we might need to be more permissive
            if self.config.ignore_ssl_errors:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                logging.warning("SSL verification disabled - use with caution")
            
            # Prepare headers with strict filtering to prevent issues
            headers = {
                'User-Agent': self.config.user_agent,
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            # Only forward essential headers to prevent "too many headers" error
            essential_headers = ['accept', 'accept-language', 'authorization', 'cookie', 'referer']
            for header_name, header_value in self.headers.items():
                header_name_lower = header_name.lower()
                if header_name_lower in essential_headers:
                    headers[header_name] = header_value
            
            # Headers are already set above
            
            # Create request
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            
            # Make the request with timeout
            with urllib.request.urlopen(req, timeout=self.config.timeout, context=ssl_context) as response:
                return {
                    'status': response.status,
                    'headers': response.headers,
                    'data': response.read()
                }
                
        except urllib.error.HTTPError as e:
            logging.error(f"HTTP Error {e.code}: {e.reason}")
            return {
                'status': e.code,
                'headers': e.headers if hasattr(e, 'headers') else {},
                'data': e.read() if hasattr(e, 'read') else b''
            }
        except urllib.error.URLError as e:
            logging.error(f"URL Error: {e.reason}")
            return None
        except ssl.SSLError as e:
            logging.error(f"SSL Error: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            return None
    
    def _send_response(self, response):
        """Send response back to client"""
        try:
            # Send status
            self.send_response(response['status'])
            
            # Process response data
            response_data = response['data']
            
            # Handle gzip compressed content
            if response['headers'].get('content-encoding') == 'gzip':
                try:
                    response_data = gzip.decompress(response_data)
                except Exception as e:
                    logging.warning(f"Failed to decompress gzip content: {e}")
            
            # Process HTML content to translate links
            content_type = response['headers'].get('content-type', '').lower()
            if 'text/html' in content_type or 'application/xhtml' in content_type:
                try:
                    response_data = self._translate_links_in_html(response_data)
                except Exception as e:
                    logging.warning(f"Failed to translate links in HTML: {e}")
            
            # Send headers with modifications for WAP compatibility
            for header_name, header_value in response['headers'].items():
                header_name_lower = header_name.lower()
                
                # Skip headers that might cause issues with old browsers
                if header_name_lower in ['content-encoding', 'transfer-encoding', 'connection']:
                    continue
                
                # Modify content-type for WAP compatibility if needed
                if header_name_lower == 'content-type':
                    # Some old WAP browsers have issues with modern content-type declarations
                    if 'text/html' in header_value.lower():
                        header_value = 'text/html'
                    elif 'text/plain' in header_value.lower():
                        header_value = 'text/plain'
                
                self.send_header(header_name, header_value)
            
            # Set content length for the processed data
            self.send_header('Content-Length', str(len(response_data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            
            # Send body
            if response_data and self.command != 'HEAD':
                self.wfile.write(response_data)
                
        except Exception as e:
            logging.error(f"Error sending response: {str(e)}")
    
    def _send_error_response(self, status, message):
        """Send error response to client"""
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()
        
        error_html = f"""
        <html>
        <head><title>Proxy Error</title></head>
        <body>
        <h1>Proxy Error</h1>
        <p>Status: {status}</p>
        <p>Message: {message}</p>
        <p>The proxy server encountered an error while trying to fulfill your request.</p>
        </body>
        </html>
        """.encode('utf-8')
        
        self.wfile.write(error_html)
    
    def _translate_links_in_html(self, html_data):
        """Translate all links in HTML to use proxy format"""
        try:
            html_content = html_data.decode('utf-8', errors='ignore')
        except:
            # If we can't decode as UTF-8, return original data
            return html_data
        
        # Proxy base URL
        proxy_base = "http://wapproxy.onrender.com/"
        
        # Replace URLs in HTML attributes using callback function
        def replace_url_in_attribute(match):
            attr_name = match.group(1)  # href=, src=, etc.
            quote_char = match.group(2)  # " or '
            url = match.group(3)
            
            # Skip if already using proxy format
            if url.startswith('http://wapproxy.onrender.com/'):
                return match.group(0)
            # Skip data URLs, javascript URLs, and fragments
            if url.startswith(('data:', 'javascript:', '#', 'mailto:')):
                return match.group(0)
            
            # Handle relative URLs
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                # Get current host from the request
                current_host = getattr(self, '_current_target_host', 'www.google.com')
                url = f'https://{current_host}{url}'
            elif not url.startswith(('http://', 'https://')):
                # Relative URL - get current host
                current_host = getattr(self, '_current_target_host', 'www.google.com')
                url = f'https://{current_host}/{url}'
            
            # Return the attribute with proxy URL
            return f'{attr_name}{quote_char}{proxy_base}{url}{quote_char}'
        
        # Pattern to match URL attributes - handle both quoted and unquoted URLs
        url_pattern = r'((?:href|src|action|background)=)(["\'])([^"\'>\s]+)\2'
        html_content = re.sub(url_pattern, replace_url_in_attribute, html_content, flags=re.IGNORECASE)
        
        # Handle JavaScript URLs in onclick, onload, etc.
        js_pattern = r'(on\w+=["\'][^"\'>]*?)(https?://[^"\'>\s]+)([^"\'>]*["\'])'
        def replace_js_url(match):
            prefix = match.group(1)
            url = match.group(2)
            suffix = match.group(3)
            proxy_url = f'{proxy_base}{url}'
            return f'{prefix}{proxy_url}{suffix}'
        
        html_content = re.sub(js_pattern, replace_js_url, html_content, flags=re.IGNORECASE)
        
        return html_content.encode('utf-8', errors='ignore')


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server for handling multiple connections"""
    daemon_threads = True
    allow_reuse_address = True


def setup_logging(log_level):
    """Setup logging configuration"""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='HTTPS-to-HTTP Proxy Server for Legacy WAP Browsers')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=80, help='Port to bind to (default: 80)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Log level (default: INFO)')
    parser.add_argument('--ignore-ssl', action='store_true', 
                       help='Ignore SSL certificate errors (use with caution)')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (compatible; WAP-Proxy/1.0)', 
                       help='User agent string to use for requests')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Update configuration
    config = ProxyConfig()
    config.timeout = args.timeout
    config.ignore_ssl_errors = args.ignore_ssl
    config.user_agent = args.user_agent
    
    # Create and configure server
    server = None
    try:
        server = ThreadedHTTPServer((args.host, args.port), HTTPSToHTTPProxyHandler)
        
        logging.info(f"Starting HTTPS-to-HTTP proxy server on {args.host}:{args.port}")
        logging.info(f"Timeout: {args.timeout}s, SSL verification: {'disabled' if args.ignore_ssl else 'enabled'}")
        logging.info("Configure your WAP browser to use this server as an HTTP proxy")
        logging.info("Example usage: Set proxy to this server's IP and port 80")
        logging.info("Press Ctrl+C to stop the server")
        
        # Start server
        server.serve_forever()
        
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        if server:
            server.shutdown()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Failed to start server: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
