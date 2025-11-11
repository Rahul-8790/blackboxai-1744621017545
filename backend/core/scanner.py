"""
Main scanner engine
Orchestrates all scanning modules
"""

from datetime import datetime
from backend.core.scope import ScopeManager
from backend.core.reporter import Reporter
from backend.modules.subdomain_enum import SubdomainEnumerator
from backend.modules.port_scan import PortScanner
from backend.modules.tech_detect import TechnologyDetector
from backend.modules.vuln_check import VulnerabilityChecker
from backend.utils.rate_limiter import RateLimiter
from backend.utils.logger import BugBountyLogger
from backend.utils.validator import extract_domain

class BugBountyScanner:
    def __init__(self, config=None):
        self.logger = BugBountyLogger()
        self.rate_limiter = RateLimiter(requests_per_second=2, burst_size=5)
        self.scope_manager = ScopeManager(logger=self.logger)
        self.reporter = Reporter(logger=self.logger)
        
        # Initialize modules
        self.subdomain_enum = SubdomainEnumerator(
            rate_limiter=self.rate_limiter,
            logger=self.logger
        )
        self.port_scanner = PortScanner(
            rate_limiter=self.rate_limiter,
            logger=self.logger
        )
        self.tech_detector = TechnologyDetector(
            rate_limiter=self.rate_limiter,
            logger=self.logger
        )
        self.vuln_checker = VulnerabilityChecker(
            rate_limiter=self.rate_limiter,
            logger=self.logger
        )
    
    def set_scope(self, in_scope_targets, out_of_scope_targets=None):
        """Set scanning scope"""
        for target in in_scope_targets:
            self.scope_manager.add_target(target, 'in')
        
        if out_of_scope_targets:
            for target in out_of_scope_targets:
                self.scope_manager.add_target(target, 'out')
        
        self.scope_manager.display_scope()
    
    def load_scope_file(self, filepath):
        """Load scope from file"""
        return self.scope_manager.load_from_file(filepath)
    
    def scan_target(self, target, scan_type='full'):
        """
        Scan a target
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan (full, recon, vuln)
        """
        # Validate scope
        domain = extract_domain(target)
        if not self.scope_manager.check_target(domain):
            self.logger.error(f"Target {target} is OUT OF SCOPE. Aborting scan.")
            return False
        
        # Initialize report
        start_time = datetime.now().isoformat()
        self.reporter.set_scan_info(target, scan_type, start_time)
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Starting {scan_type} scan of {target}")
        self.logger.info(f"{'='*60}\n")
        
        try:
            if scan_type in ['full', 'recon']:
                self._run_reconnaissance(target, domain)
            
            if scan_type in ['full', 'vuln']:
                self._run_vulnerability_checks(target, domain)
            
            # Generate reports
            self.reporter.print_summary()
            json_report = self.reporter.generate_json_report()
            md_report = self.reporter.generate_markdown_report()
            
            self.logger.success(f"\nScan completed successfully!")
            self.logger.info(f"Reports saved:")
            self.logger.info(f"  - {json_report}")
            self.logger.info(f"  - {md_report}")
            
            return True
        
        except KeyboardInterrupt:
            self.logger.warning("\nScan interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return False
    
    def _run_reconnaissance(self, target, domain):
        """Run reconnaissance modules"""
        self.logger.info("\n[RECONNAISSANCE PHASE]")
        
        # Subdomain enumeration
        self.logger.info("\n1. Subdomain Enumeration")
        subdomains = self.subdomain_enum.run_full_enumeration(domain)
        
        if subdomains:
            self.reporter.add_finding(
                severity='info',
                title=f'Discovered {len(subdomains)} Subdomains',
                description=f'Found {len(subdomains)} active subdomains for {domain}',
                evidence='\n'.join(subdomains[:20]),  # Limit to first 20
                remediation='Review subdomains for unnecessary exposure'
            )
        
        # Port scanning
        self.logger.info("\n2. Port Scanning")
        open_ports = self.port_scanner.scan_common_ports(domain)
        
        if open_ports:
            ports_str = ', '.join([f"{p['port']}/{p['service']}" for p in open_ports])
            self.reporter.add_finding(
                severity='info',
                title=f'Open Ports Detected',
                description=f'Found {len(open_ports)} open ports on {domain}',
                evidence=ports_str,
                remediation='Ensure only necessary ports are exposed'
            )
        
        # Technology detection
        self.logger.info("\n3. Technology Detection")
        if target.startswith('http'):
            url = target
        else:
            url = f'http://{target}'
        
        technologies = self.tech_detector.detect(url)
        
        if technologies:
            tech_str = '\n'.join([f"{k}: {v}" for k, v in technologies.items()])
            self.reporter.add_finding(
                severity='info',
                title='Technologies Detected',
                description=f'Identified technologies in use',
                evidence=tech_str,
                remediation='Keep all technologies updated to latest versions'
            )
    
    def _run_vulnerability_checks(self, target, domain):
        """Run vulnerability checking modules"""
        self.logger.info("\n[VULNERABILITY ASSESSMENT PHASE]")
        
        # Ensure we have a full URL
        if not target.startswith('http'):
            url = f'https://{target}'
        else:
            url = target
        
        # Security headers check
        self.logger.info("\n1. Security Headers Analysis")
        header_findings = self.vuln_checker.check_security_headers(url)
        
        for finding in header_findings:
            self.reporter.add_finding(
                severity=finding['severity'],
                title=f"Missing Security Header: {finding.get('header', 'Unknown')}",
                description=finding['description'],
                evidence=finding.get('value', 'Header not present'),
                remediation=f"Implement {finding.get('header', 'security header')} with appropriate value"
            )
        
        # SSL/TLS check
        self.logger.info("\n2. SSL/TLS Configuration")
        if url.startswith('https'):
            ssl_findings = self.vuln_checker.check_ssl_tls(domain)
            
            for finding in ssl_findings:
                self.reporter.add_finding(
                    severity=finding['severity'],
                    title=f"SSL/TLS Issue: {finding['type']}",
                    description=finding['description'],
                    evidence=finding.get('version', finding.get('cipher', 'N/A')),
                    remediation='Update SSL/TLS configuration to use strong protocols and ciphers'
                )
        
        # Sensitive files check
        self.logger.info("\n3. Sensitive Files Exposure")
        file_findings = self.vuln_checker.check_sensitive_files(url)
        
        for finding in file_findings:
            self.reporter.add_finding(
                severity=finding['severity'],
                title='Sensitive File Exposed',
                description=finding['description'],
                evidence=finding['url'],
                remediation='Remove or restrict access to sensitive files'
            )
        
        # Check robots.txt
        self.logger.info("\n4. Information Gathering")
        robots_paths = self.vuln_checker.check_robots_txt(url)
        security_txt = self.vuln_checker.check_security_txt(url)
        
        if security_txt:
            self.reporter.add_finding(
                severity='info',
                title='Security.txt Found',
                description='Security contact information is available',
                evidence=security_txt[:500],  # First 500 chars
                remediation='N/A - This is good practice'
            )
