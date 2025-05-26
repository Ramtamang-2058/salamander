import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def allow_request(self, identifier: str) -> bool:
        """Check if a request is allowed for the given identifier (e.g., IP address)."""
        current_time = time.time()
        self.requests[identifier] = [
            t for t in self.requests[identifier] if t > current_time - self.window_seconds
        ]
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        self.requests[identifier].append(current_time)
        return True
