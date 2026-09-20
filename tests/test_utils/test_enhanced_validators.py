"""Tests for enhanced input validators."""
import json
import pytest
from app.utils.validators import (
    # Original validators
    is_valid_domain, is_valid_ip, is_valid_cidr, is_valid_url,
    sanitize_filename, contains_shell_injection, validate_target_value,
    # Enhanced validators
    validate_scan_name, validate_project_name, validate_username,
    validate_email, validate_password_strength, validate_tool_flags,
    validate_timeout, validate_json_tool_settings,
)


# ============================================================================
# Original validator regression tests
# ============================================================================

class TestOriginalValidatorsStillWork:
    """Ensure original validators still work after enhancement."""

    def test_valid_domain(self):
        assert is_valid_domain('example.com') is True

    def test_valid_ip(self):
        assert is_valid_ip('192.168.1.1') is True

    def test_valid_cidr(self):
        assert is_valid_cidr('192.168.1.0/24') is True

    def test_valid_url(self):
        assert is_valid_url('https://example.com') is True

    def test_shell_injection(self):
        assert contains_shell_injection('test; rm -rf /') is True

    def test_sanitize_filename(self):
        assert sanitize_filename('test file.txt') == 'test_file.txt'

    def test_validate_target_value(self):
        valid, msg = validate_target_value('example.com', 'domain')
        assert valid is True


# ============================================================================
# validate_scan_name
# ============================================================================

class TestValidateScanName:
    """Tests for validate_scan_name."""

    def test_valid_scan_name(self):
        valid, msg = validate_scan_name('My Scan 2024')
        assert valid is True
        assert msg == ''

    def test_valid_scan_name_with_special_chars(self):
        valid, msg = validate_scan_name('Scan-1_test.com')
        assert valid is True

    def test_too_short(self):
        valid, msg = validate_scan_name('AB')
        assert valid is False
        assert 'at least 3' in msg

    def test_too_long(self):
        valid, msg = validate_scan_name('A' * 121)
        assert valid is False
        assert 'at most 120' in msg

    def test_empty_string(self):
        valid, msg = validate_scan_name('')
        assert valid is False

    def test_none(self):
        valid, msg = validate_scan_name(None)
        assert valid is False

    def test_non_string(self):
        valid, msg = validate_scan_name(123)
        assert valid is False

    def test_invalid_characters(self):
        valid, msg = validate_scan_name('Scan; DROP TABLE')
        assert valid is False
        assert 'invalid characters' in msg.lower()

    def test_exact_min_length(self):
        valid, msg = validate_scan_name('ABC')
        assert valid is True

    def test_exact_max_length(self):
        valid, msg = validate_scan_name('A' * 120)
        assert valid is True

    def test_whitespace_only_is_stripped(self):
        valid, msg = validate_scan_name('   ')
        assert valid is False


# ============================================================================
# validate_project_name
# ============================================================================

class TestValidateProjectName:
    """Tests for validate_project_name."""

    def test_valid_project_name(self):
        valid, msg = validate_project_name('My Project')
        assert valid is True

    def test_valid_with_hyphens(self):
        valid, msg = validate_project_name('My-Project_1')
        assert valid is True

    def test_too_short(self):
        valid, msg = validate_project_name('AB')
        assert valid is False

    def test_too_long(self):
        valid, msg = validate_project_name('A' * 121)
        assert valid is False

    def test_invalid_characters_dot(self):
        valid, msg = validate_project_name('Project.com')
        assert valid is False  # Dots not allowed in project names

    def test_empty(self):
        valid, msg = validate_project_name('')
        assert valid is False

    def test_none(self):
        valid, msg = validate_project_name(None)
        assert valid is False


# ============================================================================
# validate_username
# ============================================================================

class TestValidateUsername:
    """Tests for validate_username."""

    def test_valid_username(self):
        valid, msg = validate_username('john_doe123')
        assert valid is True

    def test_valid_username_simple(self):
        valid, msg = validate_username('alice')
        assert valid is True

    def test_too_short(self):
        valid, msg = validate_username('ab')
        assert valid is False
        assert 'at least 3' in msg

    def test_too_long(self):
        valid, msg = validate_username('a' * 81)
        assert valid is False
        assert 'at most 80' in msg

    def test_spaces_not_allowed(self):
        valid, msg = validate_username('john doe')
        assert valid is False

    def test_special_chars_not_allowed(self):
        valid, msg = validate_username('john@doe')
        assert valid is False

    def test_hyphen_not_allowed(self):
        valid, msg = validate_username('john-doe')
        assert valid is False

    def test_underscore_allowed(self):
        valid, msg = validate_username('john_doe')
        assert valid is True

    def test_empty(self):
        valid, msg = validate_username('')
        assert valid is False


# ============================================================================
# validate_email
# ============================================================================

class TestValidateEmail:
    """Tests for validate_email."""

    def test_valid_email(self):
        valid, msg = validate_email('user@example.com')
        assert valid is True

    def test_valid_email_with_dots(self):
        valid, msg = validate_email('user.name@example.co.uk')
        assert valid is True

    def test_valid_email_with_plus(self):
        valid, msg = validate_email('user+tag@example.com')
        assert valid is True

    def test_missing_at(self):
        valid, msg = validate_email('userexample.com')
        assert valid is False

    def test_missing_domain(self):
        valid, msg = validate_email('user@')
        assert valid is False

    def test_missing_tld(self):
        valid, msg = validate_email('user@example')
        assert valid is False

    def test_too_long(self):
        valid, msg = validate_email('a' * 255 + '@example.com')
        assert valid is False

    def test_empty(self):
        valid, msg = validate_email('')
        assert valid is False

    def test_none(self):
        valid, msg = validate_email(None)
        assert valid is False


# ============================================================================
# validate_password_strength
# ============================================================================

class TestValidatePasswordStrength:
    """Tests for validate_password_strength."""

    def test_strong_password(self):
        valid, msg = validate_password_strength('MyPass123')
        assert valid is True
        assert msg == ''

    def test_password_with_special_chars(self):
        valid, msg = validate_password_strength('MyPass123!@#')
        assert valid is True

    def test_too_short(self):
        valid, msg = validate_password_strength('Ab1')
        assert valid is False
        assert 'at least 8' in msg

    def test_no_uppercase(self):
        valid, msg = validate_password_strength('mypassword1')
        assert valid is False
        assert 'uppercase' in msg.lower()

    def test_no_lowercase(self):
        valid, msg = validate_password_strength('MYPASSWORD1')
        assert valid is False
        assert 'lowercase' in msg.lower()

    def test_no_digit(self):
        valid, msg = validate_password_strength('MyPassword')
        assert valid is False
        assert 'digit' in msg.lower()

    def test_too_long(self):
        valid, msg = validate_password_strength('A' * 129 + 'a1')
        assert valid is False
        assert 'at most 128' in msg

    def test_empty(self):
        valid, msg = validate_password_strength('')
        assert valid is False

    def test_none(self):
        valid, msg = validate_password_strength(None)
        assert valid is False

    def test_exact_8_chars(self):
        valid, msg = validate_password_strength('Abcd1234')
        assert valid is True


# ============================================================================
# validate_tool_flags
# ============================================================================

class TestValidateToolFlags:
    """Tests for validate_tool_flags."""

    def test_empty_flags_ok(self):
        valid, msg = validate_tool_flags('')
        assert valid is True

    def test_none_flags_ok(self):
        valid, msg = validate_tool_flags(None)
        assert valid is True

    def test_valid_flags(self):
        valid, msg = validate_tool_flags('-v --timeout 30 -o output')
        assert valid is True

    def test_semicolon_rejected(self):
        valid, msg = validate_tool_flags('-v; rm -rf /')
        assert valid is False

    def test_pipe_rejected(self):
        valid, msg = validate_tool_flags('-v | cat /etc/passwd')
        assert valid is False

    def test_ampersand_rejected(self):
        valid, msg = validate_tool_flags('-v & echo pwned')
        assert valid is False

    def test_dollar_sign_rejected(self):
        valid, msg = validate_tool_flags('$HOME')
        assert valid is False

    def test_backtick_rejected(self):
        valid, msg = validate_tool_flags('`whoami`')
        assert valid is False

    def test_backslash_rejected(self):
        valid, msg = validate_tool_flags('-v \\n echo pwned')
        assert valid is False

    def test_newline_rejected(self):
        valid, msg = validate_tool_flags('-v\nrm -rf /')
        assert valid is False

    def test_non_string_rejected(self):
        valid, msg = validate_tool_flags(123)
        assert valid is False

    def test_safe_hyphens_allowed(self):
        valid, msg = validate_tool_flags('--deep-scan -t 30')
        assert valid is True


# ============================================================================
# validate_timeout
# ============================================================================

class TestValidateTimeout:
    """Tests for validate_timeout."""

    def test_valid_timeout(self):
        valid, msg = validate_timeout(300)
        assert valid is True

    def test_valid_timeout_string(self):
        valid, msg = validate_timeout('300')
        assert valid is True

    def test_minimum_timeout(self):
        valid, msg = validate_timeout(60)
        assert valid is True

    def test_maximum_timeout(self):
        valid, msg = validate_timeout(7200)
        assert valid is True

    def test_below_minimum(self):
        valid, msg = validate_timeout(59)
        assert valid is False
        assert 'at least 60' in msg

    def test_above_maximum(self):
        valid, msg = validate_timeout(7201)
        assert valid is False
        assert 'at most 7200' in msg

    def test_none_is_ok(self):
        valid, msg = validate_timeout(None)
        assert valid is True

    def test_invalid_string(self):
        valid, msg = validate_timeout('abc')
        assert valid is False
        assert 'number' in msg.lower()

    def test_zero(self):
        valid, msg = validate_timeout(0)
        assert valid is False

    def test_negative(self):
        valid, msg = validate_timeout(-1)
        assert valid is False


# ============================================================================
# validate_json_tool_settings
# ============================================================================

class TestValidateJsonToolSettings:
    """Tests for validate_json_tool_settings."""

    def test_empty_string_ok(self):
        valid, msg = validate_json_tool_settings('')
        assert valid is True

    def test_none_ok(self):
        valid, msg = validate_json_tool_settings(None)
        assert valid is True

    def test_valid_json_object(self):
        valid, msg = validate_json_tool_settings('{"key": "value"}')
        assert valid is True

    def test_invalid_json(self):
        valid, msg = validate_json_tool_settings('{invalid json}')
        assert valid is False
        assert 'valid JSON' in msg

    def test_json_array_rejected(self):
        valid, msg = validate_json_tool_settings('[1, 2, 3]')
        assert valid is False
        assert 'JSON object' in msg

    def test_json_string_rejected(self):
        valid, msg = validate_json_tool_settings('"hello"')
        assert valid is False
        assert 'JSON object' in msg

    def test_json_number_rejected(self):
        valid, msg = validate_json_tool_settings('42')
        assert valid is False
        assert 'JSON object' in msg

    def test_nested_json_ok(self):
        settings = json.dumps({"level1": {"level2": {"level3": "value"}}})
        valid, msg = validate_json_tool_settings(settings)
        assert valid is True

    def test_too_deep_nesting(self):
        """Deeply nested JSON should be rejected."""
        # Create 12 levels of nesting
        obj = {"key": "val"}
        for _ in range(12):
            obj = {"nested": obj}
        settings = json.dumps(obj)
        valid, msg = validate_json_tool_settings(settings)
        assert valid is False
        assert 'too deep' in msg.lower()

    def test_non_string_rejected(self):
        valid, msg = validate_json_tool_settings(123)
        assert valid is False

    def test_complex_valid_settings(self):
        settings = json.dumps({
            "threads": 10,
            "timeout": 300,
            "options": ["--verbose", "--follow-redirects"],
            "headers": {"User-Agent": "PentestPlatform/1.0"}
        })
        valid, msg = validate_json_tool_settings(settings)
        assert valid is True
