"""
Logging utility for bug bounty toolkit
Ensures all activities are logged for accountability and compliance
"""

import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class BugBountyLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def info(self, message):
        """Log info message"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
        self.logger.info(message)
    
    def success(self, message):
        """Log success message"""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        self.logger.info(f"SUCCESS: {message}")
    
    def warning(self, message):
        """Log warning message"""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} {message}")
        self.logger.critical(message)
    
    def finding(self, severity, title, details):
        """Log security finding"""
        color = {
            "critical": Fore.RED,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.CYAN,
            "info": Fore.WHITE
        }.get(severity.lower(), Fore.WHITE)
        
        print(f"{color}[{severity.upper()}]{Style.RESET_ALL} {title}")
        print(f"  Details: {details}")
        self.logger.info(f"FINDING [{severity.upper()}]: {title} - {details}")
