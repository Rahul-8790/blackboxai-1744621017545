"""
Scope validation and input validation utilities
Ensures all scanning stays within authorized scope
"""

import re
import validators
from urllib.parse import urlparse
import ipaddress

class ScopeValidator:
    def __init__(self):
        self.in_scope = []
        self.out_of_scope = []
    
    def add_scope(self, targets, scope_type="in"):
        """
        Add targets to scope
        
        Args:
            targets: List of domains, IPs, or CIDR ranges
            scope_type: "in" or "out" of scope
        """
        target_list = self.in_scope if scope_type == "in" else self.out_of_scope
        
        for target in targets:
            target = target.strip()
            if target and target not in target_list:
                target_list.append(target)
    
    def is_in_scope(self, target):
        """
        Check if target is in scope
        
        Args:
            target: Domain, IP, or URL to check
            
        Returns:
            bool: True if in scope, False otherwise
        """
        # Parse target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target
        
        # Check if explicitly out of scope
        if self._matches_any(domain, self.out_of_scope):
            return False
        
        # Check if in scope
        if self._matches_any(domain, self.in_scope):
            return True
        
        return False
    
    def _matches_any(self, target, scope_list):
        """Check if target matches any item in scope list"""
        for scope_item in scope_list:
            if self._matches_scope(target, scope_item):
                return True
        return False
    
    def _matches_scope(self, target, scope_item):
        """Check if target matches a scope item"""
        # Wildcard subdomain matching
        if scope_item.startswith('*.'):
            base_domain = scope_item[2:]
            if target == base_domain or target.endswith('.' + base_domain):
                return True
        
        # Exact match
        if target == scope_item:
            return True
        
        # CIDR range matching for IPs
        try:
            target_ip = ipaddress.ip_address(target)
            scope_network = ipaddress.ip_network(scope_item, strict=False)
            if target_ip in scope_network:
                return True
        except ValueError:
            pass
        
        return False
    
    def get_scope_summary(self):
        """Get summary of current scope"""
        return {
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "total_in_scope": len(self.in_scope),
            "total_out_of_scope": len(self.out_of_scope)
        }

def validate_domain(domain):
    """Validate domain name"""
    return validators.domain(domain) is True

def validate_url(url):
    """Validate URL"""
    return validators.url(url) is True

def validate_ip(ip):
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(input_str):
    """Sanitize user input to prevent injection"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$]', '', input_str)
    return sanitized.strip()

def extract_domain(url):
    """Extract domain from URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    return parsed.netloc
