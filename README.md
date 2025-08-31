# HTTPS-to-HTTP Proxy Server for Legacy WAP Browsers

This Python application creates a proxy server that translates HTTPS requests to HTTP for legacy WAP browsers on old mobile devices that cannot handle modern SSL/TLS connections.

## Features

- HTTP proxy server that accepts requests from old phones
- Translates incoming HTTP requests to HTTPS requests to target websites
- Returns website content back to the phone via HTTP
- Handles basic error scenarios (connection failures, SSL issues)
- Simple configuration for proxy settings
- Logging for debugging connection issues
- Command-line interface for easy configuration

## Requirements

- Python 3.6 or higher
- No additional packages required (uses only built-in libraries)

## Installation

1. Download the files to your computer:
   - `proxy_server.py`
   - `config.py`

2. Make the server executable (Linux/Mac):
   ```bash
   chmod +x proxy_server.py
   ```

## Usage

### Basic Usage

Start the proxy server with default settings:

```bash
python proxy_server.py
