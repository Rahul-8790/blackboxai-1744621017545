"""
Port scanning module with rate limiting
Ethical port scanning for bug bounty reconnaissance
"""

import socket
import concurrent.futures
from backend.utils.rate_limiter import RateLimiter
from backend.utils.logger import BugBountyLogger

class PortScanner:
    def __init__(self, rate_limiter=None, logger=None):
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=5)
        self.logger = logger or BugBountyLogger()
        self.open_ports = []
    
    def scan_port(self, host, port, timeout=3):
        """
        Scan a single port
        
        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout
            
        Returns:
            dict: Port info if open, None if closed
        """
        self.rate_limiter.acquire()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self._get_service_name(port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service
                }
        except socket.gaierror:
            self.logger.error(f"Hostname could not be resolved: {host}")
        except socket.error as e:
            self.logger.warning(f"Connection error on port {port}: {e}")
        
        return None
    
    def _get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8000: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt"
        }
        return services.get(port, "Unknown")
    
    def scan_ports(self, host, ports, max_workers=5):
        """
        Scan multiple ports
        
        Args:
            host: Target host
            ports: List of ports to scan
            max_workers: Maximum concurrent scans
            
        Returns:
            List of open ports
        """
        self.logger.info(f"Scanning {len(ports)} ports on {host}...")
        self.open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    self.logger.success(f"  Port {result['port']}/tcp open - {result['service']}")
        
        self.logger.success(f"Scan complete: {len(self.open_ports)} open ports found")
        return self.open_ports
    
    def scan_common_ports(self, host):
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                       1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888]
        return self.scan_ports(host, common_ports)
    
    def scan_web_ports(self, host):
        """Scan common web ports"""
        web_ports = [80, 443, 8000, 8080, 8443, 8888, 3000, 5000]
        return self.scan_ports(host, web_ports)
    
    def get_results(self):
        """Get scan results"""
        return self.open_ports
