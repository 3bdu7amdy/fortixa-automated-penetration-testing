"""Tests for the RateLimiter utility."""
import time
import threading
import pytest
from app.utils.rate_limiter import RateLimiter, get_rate_limiter


class TestRateLimiterBasic:
    """Test basic rate limiting functionality."""

    def setup_method(self):
        """Create a fresh rate limiter for each test."""
        self.limiter = RateLimiter()

    def test_allows_request_under_limit(self):
        """Requests under the limit should be allowed."""
        allowed, retry_after = self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
        assert allowed is True
        assert retry_after is None

    def test_blocks_request_over_limit(self):
        """Requests exceeding the limit should be blocked."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)

        allowed, retry_after = self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
        assert allowed is False
        assert retry_after is not None
        assert retry_after > 0

    def test_separate_keys_independent(self):
        """Different keys should have independent rate limits."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)

        # user2 should still be allowed
        allowed, _ = self.limiter.is_allowed('user2', max_requests=5, window_seconds=60)
        assert allowed is True

    def test_same_key_different_endpoints(self):
        """Same key string should share the limit (endpoint prefix handled by decorator)."""
        for _ in range(3):
            self.limiter.is_allowed('key1', max_requests=3, window_seconds=60)

        allowed, _ = self.limiter.is_allowed('key1', max_requests=3, window_seconds=60)
        assert allowed is False

    def test_retry_after_is_positive(self):
        """retry_after should be a positive integer when blocked."""
        self.limiter.is_allowed('user1', max_requests=1, window_seconds=10)

        # Second request should be blocked
        _, retry_after = self.limiter.is_allowed('user1', max_requests=1, window_seconds=10)
        assert retry_after is not None
        assert retry_after > 0
        assert retry_after <= 10


class TestRateLimiterSlidingWindow:
    """Test sliding window behavior."""

    def setup_method(self):
        self.limiter = RateLimiter()

    def test_window_expires_allows_new_requests(self):
        """After the window expires, new requests should be allowed."""
        # Use a very short window
        for _ in range(3):
            self.limiter.is_allowed('user1', max_requests=3, window_seconds=1)

        # Should be blocked
        allowed, _ = self.limiter.is_allowed('user1', max_requests=3, window_seconds=1)
        assert allowed is False

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        allowed, _ = self.limiter.is_allowed('user1', max_requests=3, window_seconds=1)
        assert allowed is True

    def test_partial_window_expiry(self):
        """Older requests should expire while newer ones stay."""
        # Use a 4-second window for clearer timing
        # Make request 1
        self.limiter.is_allowed('user1', max_requests=2, window_seconds=4)
        # Small gap
        time.sleep(0.3)
        # Make request 2
        self.limiter.is_allowed('user1', max_requests=2, window_seconds=4)

        # Third should be blocked
        allowed, _ = self.limiter.is_allowed('user1', max_requests=2, window_seconds=4)
        assert allowed is False

        # Wait until request 1 has expired but request 2 hasn't
        # Request 1 was ~0.3s ago, request 2 was ~0s ago
        # After 3.5s: request 1 is ~3.8s old (expired for 4s window)
        #              request 2 is ~3.5s old (still in window)
        time.sleep(3.8)

        # Now request 1 has expired, one slot freed, should be allowed
        allowed, _ = self.limiter.is_allowed('user1', max_requests=2, window_seconds=4)
        assert allowed is True


class TestRateLimiterGetRemaining:
    """Test get_remaining functionality."""

    def setup_method(self):
        self.limiter = RateLimiter()

    def test_remaining_starts_at_max(self):
        """Remaining should start at max_requests for a new key."""
        remaining = self.limiter.get_remaining('user1', max_requests=10, window_seconds=60)
        assert remaining == 10

    def test_remaining_decreases_with_requests(self):
        """Remaining should decrease as requests are made."""
        self.limiter.is_allowed('user1', max_requests=10, window_seconds=60)
        self.limiter.is_allowed('user1', max_requests=10, window_seconds=60)

        remaining = self.limiter.get_remaining('user1', max_requests=10, window_seconds=60)
        assert remaining == 8

    def test_remaining_zero_when_exceeded(self):
        """Remaining should be 0 when limit is exceeded."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)

        remaining = self.limiter.get_remaining('user1', max_requests=5, window_seconds=60)
        assert remaining == 0

    def test_remaining_does_not_consume_request(self):
        """get_remaining should NOT consume a request slot."""
        self.limiter.get_remaining('user1', max_requests=5, window_seconds=60)
        remaining = self.limiter.get_remaining('user1', max_requests=5, window_seconds=60)
        assert remaining == 5


class TestRateLimiterReset:
    """Test reset functionality."""

    def setup_method(self):
        self.limiter = RateLimiter()

    def test_reset_specific_key(self):
        """Resetting a specific key should allow new requests for that key."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)

        # Should be blocked
        allowed, _ = self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
        assert allowed is False

        # Reset user1
        self.limiter.reset('user1')

        # Should be allowed again
        allowed, _ = self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
        assert allowed is True

    def test_reset_does_not_affect_other_keys(self):
        """Resetting one key should not affect other keys."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
            self.limiter.is_allowed('user2', max_requests=5, window_seconds=60)

        self.limiter.reset('user1')

        # user2 should still be blocked
        allowed, _ = self.limiter.is_allowed('user2', max_requests=5, window_seconds=60)
        assert allowed is False

    def test_reset_all_keys(self):
        """Resetting all keys should clear everything."""
        for _ in range(5):
            self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
            self.limiter.is_allowed('user2', max_requests=5, window_seconds=60)

        self.limiter.reset()

        # Both should be allowed
        allowed1, _ = self.limiter.is_allowed('user1', max_requests=5, window_seconds=60)
        allowed2, _ = self.limiter.is_allowed('user2', max_requests=5, window_seconds=60)
        assert allowed1 is True
        assert allowed2 is True


class TestRateLimiterCleanup:
    """Test cleanup functionality."""

    def setup_method(self):
        self.limiter = RateLimiter()

    def test_cleanup_removes_expired_keys(self):
        """Cleanup should remove keys with no recent requests."""
        # Make a request with a short window
        self.limiter.is_allowed('old_key', max_requests=5, window_seconds=1)

        # Wait for it to expire
        time.sleep(1.1)

        # Cleanup
        self.limiter.cleanup(window_seconds=1)

        # The old key should be cleaned up - remaining should show full limit
        remaining = self.limiter.get_remaining('old_key', max_requests=5, window_seconds=1)
        assert remaining == 5


class TestRateLimiterThreadSafety:
    """Test thread safety of the rate limiter."""

    def test_concurrent_requests(self):
        """Rate limiter should be safe under concurrent access."""
        limiter = RateLimiter()
        results = []
        errors = []

        def make_requests(key, count):
            try:
                for _ in range(count):
                    allowed, _ = limiter.is_allowed(key, max_requests=50, window_seconds=60)
                    results.append(allowed)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(10):
            t = threading.Thread(target=make_requests, args=('shared_key', 10))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        # 10 threads * 10 requests = 100 total, but only 50 should be allowed
        allowed_count = sum(1 for r in results if r)
        blocked_count = sum(1 for r in results if not r)
        assert allowed_count == 50
        assert blocked_count == 50


class TestGetRateLimiter:
    """Test the module-level singleton."""

    def test_get_rate_limiter_returns_instance(self):
        """get_rate_limiter should return a RateLimiter instance."""
        limiter = get_rate_limiter()
        assert isinstance(limiter, RateLimiter)

    def test_get_rate_limiter_returns_same_instance(self):
        """get_rate_limiter should return the same instance each time."""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2
