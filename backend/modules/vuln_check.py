"""
Vulnerability checking module
Non-intrusive security checks for common vulnerabilities
"""

import requests
import ssl
import socket
from urllib.parse import urlparse
from backend.utils.rate_limiter import RateLimiter
from backend.utils.logger import BugBountyLogger

class VulnerabilityChecker:
    def __init__(self, rate_limiter=None, logger=None):
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=2)
        self.logger = logger or BugBountyLogger()
        self.vulnerabilities = []
    
    def check_security_headers(self, url):
        """
        Check for missing security headers
        
        Args:
            url: Target URL
            
        Returns:
            List of missing/misconfigured headers
        """
        self.logger.info(f"Checking security headers for {url}...")
        
        try:
            self.rate_limiter.acquire()
            
            headers = {
                'User-Agent': 'BugBountyToolkit/1.0 (Ethical Security Research)'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': {
                    'severity': 'medium',
                    'description': 'HSTS header missing - site vulnerable to SSL stripping attacks'
                },
                'X-Frame-Options': {
                    'severity': 'medium',
                    'description': 'X-Frame-Options missing - site vulnerable to clickjacking'
                },
                'X-Content-Type-Options': {
                    'severity': 'low',
                    'description': 'X-Content-Type-Options missing - MIME sniffing possible'
                },
                'Content-Security-Policy': {
                    'severity': 'medium',
                    'description': 'CSP header missing - XSS protection not implemented'
                },
                'X-XSS-Protection': {
                    'severity': 'low',
                    'description': 'X-XSS-Protection missing or disabled'
                },
                'Referrer-Policy': {
                    'severity': 'low',
                    'description': 'Referrer-Policy missing - referrer information may leak'
                },
                'Permissions-Policy': {
                    'severity': 'info',
                    'description': 'Permissions-Policy missing - browser features not restricted'
                }
            }
            
            findings = []
            for header, info in security_headers.items():
                if header not in response.headers:
                    finding = {
                        'type': 'missing_security_header',
                        'severity': info['severity'],
                        'header': header,
                        'description': info['description']
                    }
                    findings.append(finding)
                    self.vulnerabilities.append(finding)
                    self.logger.warning(f"  Missing: {header}")
                else:
                    self.logger.info(f"  Present: {header}")
            
            # Check for insecure headers
            if 'Server' in response.headers:
                server = response.headers['Server']
                if any(version in server for version in ['/', '.']):
                    finding = {
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'header': 'Server',
                        'value': server,
                        'description': 'Server header discloses version information'
                    }
                    findings.append(finding)
                    self.vulnerabilities.append(finding)
                    self.logger.warning(f"  Info Disclosure: Server header reveals version")
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error checking security headers: {e}")
            return []
    
    def check_ssl_tls(self, hostname, port=443):
        """
        Check SSL/TLS configuration
        
        Args:
            hostname: Target hostname
            port: HTTPS port (default 443)
            
        Returns:
            SSL/TLS findings
        """
        self.logger.info(f"Checking SSL/TLS for {hostname}:{port}...")
        
        findings = []
        
        try:
            self.rate_limiter.acquire()
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    self.logger.info(f"  SSL/TLS Version: {version}")
                    self.logger.info(f"  Cipher: {cipher[0]}")
                    
                    # Check for weak protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        finding = {
                            'type': 'weak_ssl_version',
                            'severity': 'high',
                            'version': version,
                            'description': f'Weak SSL/TLS version {version} is supported'
                        }
                        findings.append(finding)
                        self.vulnerabilities.append(finding)
                        self.logger.warning(f"  Weak protocol: {version}")
                    
                    # Check cipher strength
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        finding = {
                            'type': 'weak_cipher',
                            'severity': 'medium',
                            'cipher': cipher[0],
                            'description': f'Weak cipher {cipher[0]} is in use'
                        }
                        findings.append(finding)
                        self.vulnerabilities.append(finding)
                        self.logger.warning(f"  Weak cipher: {cipher[0]}")
                    
                    # Check certificate
                    if cert:
                        subject = dict(x[0] for x in cert['subject'])
                        self.logger.info(f"  Certificate CN: {subject.get('commonName', 'N/A')}")
        
        except ssl.SSLError as e:
            self.logger.error(f"SSL Error: {e}")
        except Exception as e:
            self.logger.error(f"Error checking SSL/TLS: {e}")
        
        return findings
    
    def check_sensitive_files(self, base_url, wordlist_path='wordlists/sensitive_files.txt'):
        """
        Check for exposed sensitive files
        
        Args:
            base_url: Base URL to check
            wordlist_path: Path to sensitive files wordlist
            
        Returns:
            List of exposed files
        """
        self.logger.info(f"Checking for sensitive files on {base_url}...")
        
        # Default sensitive files if wordlist not found
        sensitive_files = [
            '.env', '.git/config', 'config.php', 'wp-config.php',
            '.htpasswd', 'phpinfo.php', 'backup.sql', '.DS_Store'
        ]
        
        # Try to load wordlist
        try:
            with open(wordlist_path, 'r') as f:
                sensitive_files = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.warning(f"Wordlist not found: {wordlist_path}, using defaults")
        
        findings = []
        base_url = base_url.rstrip('/')
        
        for file_path in sensitive_files:
            try:
                self.rate_limiter.acquire()
                
                url = f"{base_url}/{file_path}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    finding = {
                        'type': 'sensitive_file_exposed',
                        'severity': 'high',
                        'url': url,
                        'status_code': response.status_code,
                        'description': f'Sensitive file exposed: {file_path}'
                    }
                    findings.append(finding)
                    self.vulnerabilities.append(finding)
                    self.logger.warning(f"  Exposed: {file_path} (Status: {response.status_code})")
            
            except requests.RequestException:
                pass
        
        if not findings:
            self.logger.success("No sensitive files found exposed")
        
        return findings
    
    def check_robots_txt(self, base_url):
        """
        Check robots.txt for interesting paths
        
        Args:
            base_url: Base URL
            
        Returns:
            Interesting paths from robots.txt
        """
        self.logger.info(f"Checking robots.txt for {base_url}...")
        
        try:
            self.rate_limiter.acquire()
            
            url = f"{base_url.rstrip('/')}/robots.txt"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                self.logger.success("robots.txt found")
                
                disallowed_paths = []
                for line in response.text.split('\n'):
                    if line.strip().startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                
                if disallowed_paths:
                    self.logger.info(f"  Found {len(disallowed_paths)} disallowed paths")
                    return disallowed_paths
            else:
                self.logger.info("robots.txt not found")
        
        except Exception as e:
            self.logger.error(f"Error checking robots.txt: {e}")
        
        return []
    
    def check_security_txt(self, base_url):
        """
        Check for security.txt file
        
        Args:
            base_url: Base URL
            
        Returns:
            Security.txt content if found
        """
        self.logger.info(f"Checking security.txt for {base_url}...")
        
        locations = [
            '/.well-known/security.txt',
            '/security.txt'
        ]
        
        for location in locations:
            try:
                self.rate_limiter.acquire()
                
                url = f"{base_url.rstrip('/')}{location}"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    self.logger.success(f"security.txt found at {location}")
                    return response.text
            
            except Exception:
                pass
        
        self.logger.info("security.txt not found")
        return None
    
    def get_results(self):
        """Get all vulnerability findings"""
        return self.vulnerabilities
