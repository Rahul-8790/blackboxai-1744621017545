"""
Technology detection module
Identifies technologies used by target applications
"""

import requests
import re
from bs4 import BeautifulSoup
from backend.utils.rate_limiter import RateLimiter
from backend.utils.logger import BugBountyLogger

class TechnologyDetector:
    def __init__(self, rate_limiter=None, logger=None):
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=2)
        self.logger = logger or BugBountyLogger()
        self.technologies = {}
    
    def detect(self, url):
        """
        Detect technologies used by a website
        
        Args:
            url: Target URL
            
        Returns:
            dict: Detected technologies
        """
        self.logger.info(f"Detecting technologies for {url}...")
        
        try:
            self.rate_limiter.acquire()
            
            headers = {
                'User-Agent': 'BugBountyToolkit/1.0 (Ethical Security Research)'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Analyze headers
            self._analyze_headers(response.headers)
            
            # Analyze HTML content
            if 'text/html' in response.headers.get('Content-Type', ''):
                self._analyze_html(response.text)
            
            # Analyze cookies
            self._analyze_cookies(response.cookies)
            
            self.logger.success(f"Detected {len(self.technologies)} technologies")
            
        except Exception as e:
            self.logger.error(f"Error detecting technologies: {e}")
        
        return self.technologies
    
    def _analyze_headers(self, headers):
        """Analyze HTTP headers for technology fingerprints"""
        # Server header
        if 'Server' in headers:
            server = headers['Server']
            self.technologies['server'] = server
            self.logger.info(f"  Server: {server}")
        
        # X-Powered-By header
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            self.technologies['powered_by'] = powered_by
            self.logger.info(f"  Powered By: {powered_by}")
        
        # Framework-specific headers
        framework_headers = {
            'X-AspNet-Version': 'ASP.NET',
            'X-AspNetMvc-Version': 'ASP.NET MVC',
            'X-Drupal-Cache': 'Drupal',
            'X-Generator': 'Generator',
            'X-Powered-CMS': 'CMS'
        }
        
        for header, tech in framework_headers.items():
            if header in headers:
                self.technologies[tech.lower().replace(' ', '_')] = headers[header]
                self.logger.info(f"  {tech}: {headers[header]}")
    
    def _analyze_html(self, html):
        """Analyze HTML content for technology fingerprints"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Meta generator tag
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            self.technologies['generator'] = generator['content']
            self.logger.info(f"  Generator: {generator['content']}")
        
        # WordPress detection
        if 'wp-content' in html or 'wp-includes' in html:
            self.technologies['cms'] = 'WordPress'
            self.logger.info("  CMS: WordPress")
            
            # Try to detect WordPress version
            version_match = re.search(r'wp-includes/.*?ver=([0-9.]+)', html)
            if version_match:
                self.technologies['wordpress_version'] = version_match.group(1)
        
        # Joomla detection
        if 'Joomla' in html or '/components/com_' in html:
            self.technologies['cms'] = 'Joomla'
            self.logger.info("  CMS: Joomla")
        
        # Drupal detection
        if 'Drupal' in html or '/sites/default/' in html:
            self.technologies['cms'] = 'Drupal'
            self.logger.info("  CMS: Drupal")
        
        # JavaScript frameworks
        js_frameworks = {
            'react': ['react', 'reactjs'],
            'angular': ['angular', 'ng-'],
            'vue': ['vue.js', 'vuejs'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap']
        }
        
        for framework, patterns in js_frameworks.items():
            for pattern in patterns:
                if pattern in html.lower():
                    self.technologies[f'js_{framework}'] = 'Detected'
                    self.logger.info(f"  JavaScript: {framework.capitalize()}")
                    break
    
    def _analyze_cookies(self, cookies):
        """Analyze cookies for technology fingerprints"""
        cookie_patterns = {
            'PHPSESSID': 'PHP',
            'JSESSIONID': 'Java/JSP',
            'ASP.NET_SessionId': 'ASP.NET',
            'laravel_session': 'Laravel',
            'django': 'Django',
            'express': 'Express.js'
        }
        
        for cookie_name, tech in cookie_patterns.items():
            if cookie_name in cookies:
                self.technologies['backend'] = tech
                self.logger.info(f"  Backend: {tech}")
                break
    
    def get_results(self):
        """Get detected technologies"""
        return self.technologies
