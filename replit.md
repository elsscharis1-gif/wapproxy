# HTTPS-to-HTTP Proxy Server for Legacy WAP Browsers

## Overview

This project is a Python-based proxy server designed to bridge the gap between legacy WAP browsers on old mobile devices and modern HTTPS websites. The server accepts HTTP requests from devices that cannot handle SSL/TLS connections and translates them to HTTPS requests for target websites, then returns the content back via HTTP. This enables old mobile phones to access modern websites that have migrated to HTTPS-only configurations.

The system is built using Python's built-in libraries without external dependencies, making it lightweight and easy to deploy. It includes features like domain filtering, content simplification for WAP browsers, request logging, and configurable security settings.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

**Core Architecture Pattern**: HTTP Proxy Server with Request Translation
- **Design Approach**: Single-threaded HTTP server using Python's built-in `http.server` module
- **Request Flow**: Incoming HTTP requests → URL parsing → HTTPS translation → Response forwarding
- **Configuration Management**: Environment variable-based configuration with fallback defaults

**Server Components**:
- `HTTPSToHTTPProxyHandler`: Main request handler extending BaseHTTPRequestHandler
- `ProxyConfig`: Configuration management class handling environment variables
- Built-in Python HTTP server for handling incoming connections

**Request Processing**:
- Supports standard HTTP methods (GET, POST, HEAD, PUT, DELETE)
- URL parsing and reconstruction for HTTPS endpoints
- Request header forwarding with custom User-Agent
- Response size limiting for memory management

**Security Features**:
- Domain allowlist/blocklist functionality
- SSL error handling with configurable ignore option
- Response size limits to prevent memory exhaustion
- Request timeout configuration

**WAP Browser Optimizations**:
- Optional HTML simplification
- JavaScript stripping capability
- CSS removal options
- Custom User-Agent for WAP compatibility

**Error Handling**:
- Connection failure management
- SSL/TLS error handling
- HTTP status code translation
- Comprehensive logging for debugging

## External Dependencies

**Core Dependencies**: None (uses only Python standard library)
- `http.server`: HTTP server implementation
- `urllib`: URL parsing and HTTP request handling
- `ssl`: SSL/TLS connection management
- `logging`: Request and error logging
- `socketserver`: Network server framework

**Runtime Environment**:
- Python 3.6 or higher required
- No package manager dependencies
- Environment variable configuration support

**Network Requirements**:
- Outbound HTTPS connectivity to target websites
- Inbound HTTP connectivity for legacy device access
- Configurable timeout settings for connection management

**Configuration Sources**:
- Environment variables for runtime configuration
- Default fallback values in configuration class
- Command-line argument support for server parameters