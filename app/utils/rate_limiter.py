"""Simple in-memory rate limiter using sliding window."""
import threading
import time


class RateLimiter:
    """Thread-safe in-memory rate limiter using sliding window algorithm.

    Tracks request timestamps per key and enforces a maximum number
    of requests within a configurable time window.
    """

    def __init__(self):
        self._requests = {}  # {key: [timestamps]}
        self._lock = threading.Lock()

    def is_allowed(self, key, max_requests, window_seconds):
        """Check if a request is allowed for the given key.

        Args:
            key: Identifier (e.g., IP address or user_id).
            max_requests: Maximum requests allowed in the window.
            window_seconds: Time window in seconds.

        Returns:
            Tuple of (allowed: bool, retry_after: int or None).
            retry_after is the number of seconds until the oldest request
            expires from the window, or None if the request is allowed.
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            if key not in self._requests:
                self._requests[key] = []

            # Remove timestamps outside the sliding window
            self._requests[key] = [
                ts for ts in self._requests[key] if ts > window_start
            ]

            if len(self._requests[key]) < max_requests:
                self._requests[key].append(now)
                return True, None
            else:
                # Calculate retry_after: time until the oldest request expires
                oldest = self._requests[key][0]
                retry_after = int(oldest + window_seconds - now) + 1
                return False, max(retry_after, 1)

    def get_remaining(self, key, max_requests, window_seconds):
        """Get the number of remaining requests for a key.

        Args:
            key: Identifier (e.g., IP address or user_id).
            max_requests: Maximum requests allowed in the window.
            window_seconds: Time window in seconds.

        Returns:
            Number of remaining requests (0 if limit exceeded).
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            if key not in self._requests:
                return max_requests

            # Remove timestamps outside the sliding window
            self._requests[key] = [
                ts for ts in self._requests[key] if ts > window_start
            ]

            remaining = max_requests - len(self._requests[key])
            return max(remaining, 0)

    def reset(self, key=None):
        """Reset rate limit data.

        Args:
            key: If provided, reset only this key. Otherwise, reset all.
        """
        with self._lock:
            if key is None:
                self._requests.clear()
            else:
                self._requests.pop(key, None)

    def cleanup(self, window_seconds=3600):
        """Remove expired entries to prevent memory leaks.

        Args:
            window_seconds: Remove keys with no requests newer than this.
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            keys_to_remove = []
            for key, timestamps in self._requests.items():
                # Filter out old timestamps
                filtered = [ts for ts in timestamps if ts > cutoff]
                if filtered:
                    self._requests[key] = filtered
                else:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self._requests[key]


# Module-level singleton for application-wide use
_rate_limiter = RateLimiter()


def get_rate_limiter():
    """Get the global RateLimiter instance."""
    return _rate_limiter
