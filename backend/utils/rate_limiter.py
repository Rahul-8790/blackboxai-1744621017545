"""
Rate limiter to ensure ethical scanning and avoid DoS
Implements token bucket algorithm for rate limiting
"""

import time
import threading
from collections import deque

class RateLimiter:
    def __init__(self, requests_per_second=2, burst_size=5):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Maximum sustained request rate
            burst_size: Maximum burst of requests allowed
        """
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.request_times = deque(maxlen=100)
    
    def acquire(self):
        """
        Acquire permission to make a request
        Blocks until a token is available
        """
        with self.lock:
            now = time.time()
            
            # Add tokens based on time elapsed
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.requests_per_second
            )
            self.last_update = now
            
            # Wait if no tokens available
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1
            
            self.request_times.append(now)
    
    def get_stats(self):
        """Get rate limiting statistics"""
        with self.lock:
            if len(self.request_times) < 2:
                return {
                    "requests_made": len(self.request_times),
                    "average_rate": 0,
                    "tokens_available": self.tokens
                }
            
            time_span = self.request_times[-1] - self.request_times[0]
            avg_rate = len(self.request_times) / time_span if time_span > 0 else 0
            
            return {
                "requests_made": len(self.request_times),
                "average_rate": round(avg_rate, 2),
                "tokens_available": round(self.tokens, 2)
            }

class ExponentialBackoff:
    def __init__(self, base_delay=1, max_delay=60, factor=2):
        """
        Exponential backoff for retries
        
        Args:
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            factor: Multiplication factor for each retry
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.factor = factor
        self.attempt = 0
    
    def wait(self):
        """Wait with exponential backoff"""
        delay = min(self.base_delay * (self.factor ** self.attempt), self.max_delay)
        time.sleep(delay)
        self.attempt += 1
    
    def reset(self):
        """Reset backoff counter"""
        self.attempt = 0
