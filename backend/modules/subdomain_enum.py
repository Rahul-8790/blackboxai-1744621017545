"""
Subdomain enumeration module
Uses passive techniques to discover subdomains
"""

import requests
import dns.resolver
import time
from urllib.parse import urlparse
from backend.utils.rate_limiter import RateLimiter
from backend.utils.logger import BugBountyLogger

class SubdomainEnumerator:
    def __init__(self, rate_limiter=None, logger=None):
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=2)
        self.logger = logger or BugBountyLogger()
        self.subdomains = set()
    
    def enumerate_crtsh(self, domain):
        """
        Enumerate subdomains using crt.sh (Certificate Transparency)
        This is a passive, non-intrusive method
        """
        self.logger.info(f"Querying crt.sh for {domain}...")
        
        try:
            self.rate_limiter.acquire()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple names separated by newlines
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain.endswith(domain):
                            self.subdomains.add(subdomain)
                
                self.logger.success(f"Found {len(self.subdomains)} subdomains from crt.sh")
            else:
                self.logger.warning(f"crt.sh returned status {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {e}")
    
    def enumerate_dns_dumpster(self, domain):
        """
        Placeholder for DNSDumpster enumeration
        Note: Requires API key or web scraping (not implemented for compliance)
        """
        self.logger.info(f"DNS Dumpster enumeration for {domain} (not implemented)")
        # This would require proper API access or permission
        pass
    
    def verify_subdomains(self):
        """
        Verify discovered subdomains via DNS resolution
        """
        self.logger.info(f"Verifying {len(self.subdomains)} subdomains...")
        verified = set()
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for subdomain in self.subdomains:
            try:
                self.rate_limiter.acquire()
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    verified.add(subdomain)
                    self.logger.info(f"  ✓ {subdomain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                self.logger.warning(f"Error resolving {subdomain}: {e}")
        
        self.logger.success(f"Verified {len(verified)} active subdomains")
        return verified
    
    def enumerate_common_subdomains(self, domain, wordlist=None):
        """
        Enumerate common subdomains using a wordlist
        Note: This is more intrusive and should be used carefully
        """
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test']
        
        self.logger.info(f"Testing {len(wordlist)} common subdomains...")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        found = []
        for prefix in wordlist:
            subdomain = f"{prefix}.{domain}"
            try:
                self.rate_limiter.acquire()
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    found.append(subdomain)
                    self.subdomains.add(subdomain)
                    self.logger.success(f"  Found: {subdomain}")
            except:
                pass
        
        return found
    
    def get_results(self):
        """Get all discovered subdomains"""
        return sorted(list(self.subdomains))
    
    def run_full_enumeration(self, domain):
        """
        Run full subdomain enumeration
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Passive enumeration via Certificate Transparency
        self.enumerate_crtsh(domain)
        
        # Verify discovered subdomains
        verified = self.verify_subdomains()
        
        self.logger.success(f"Enumeration complete: {len(verified)} verified subdomains")
        
        return list(verified)
