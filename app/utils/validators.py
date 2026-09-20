"""Input validation helpers for security and data integrity."""
import re
import json
import ipaddress


# ============================================================================
# Original target/network validators
# ============================================================================

def is_valid_domain(domain):
    """Check if a string is a valid domain name."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip):
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr):
    """Check if a string is valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_url(url):
    """Check if a string is a valid URL with http or https scheme."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def sanitize_filename(filename):
    """Remove dangerous characters from a filename."""
    return re.sub(r'[^\w\-.]', '_', filename)


def contains_shell_injection(value):
    """Check if a string contains potential shell injection characters."""
    dangerous = [';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    return any(char in value for char in dangerous)


def validate_target_value(value, target_type):
    """Validate a target value based on its type."""
    if not value or not value.strip():
        return False, 'Target value is required'

    value = value.strip()

    if contains_shell_injection(value):
        return False, 'Target contains invalid characters'

    validators = {
        'domain': is_valid_domain,
        'ip': is_valid_ip,
        'cidr': is_valid_cidr,
        'url': is_valid_url,
    }

    validator = validators.get(target_type)
    if validator and not validator(value):
        return False, f'Invalid {target_type} format'

    return True, 'Valid'


# ============================================================================
# Enhanced validators for production hardening
# ============================================================================

def validate_scan_name(name):
    """Validate a scan name.

    Args:
        name: The scan name string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
        error_message is empty string when valid.
    """
    if not name or not isinstance(name, str):
        return False, 'Scan name is required'

    name = name.strip()

    if len(name) < 3:
        return False, 'Scan name must be at least 3 characters'

    if len(name) > 120:
        return False, 'Scan name must be at most 120 characters'

    # Only allow safe characters: alphanumeric, spaces, hyphens, underscores, dots
    if not re.match(r'^[a-zA-Z0-9 _\-.]+$', name):
        return False, 'Scan name contains invalid characters'

    return True, ''


def validate_project_name(name):
    """Validate a project name.

    Args:
        name: The project name string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not name or not isinstance(name, str):
        return False, 'Project name is required'

    name = name.strip()

    if len(name) < 3:
        return False, 'Project name must be at least 3 characters'

    if len(name) > 120:
        return False, 'Project name must be at most 120 characters'

    # Only allow safe characters: alphanumeric, spaces, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9 _\-]+$', name):
        return False, 'Project name contains invalid characters'

    return True, ''


def validate_username(username):
    """Validate a username.

    Args:
        username: The username string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not username or not isinstance(username, str):
        return False, 'Username is required'

    username = username.strip()

    if len(username) < 3:
        return False, 'Username must be at least 3 characters'

    if len(username) > 80:
        return False, 'Username must be at most 80 characters'

    # Only alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, 'Username must contain only letters, numbers, and underscores'

    return True, ''


def validate_email(email):
    """Validate an email address format.

    Args:
        email: The email string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not email or not isinstance(email, str):
        return False, 'Email is required'

    email = email.strip()

    if len(email) > 254:
        return False, 'Email is too long'

    # Basic email format check
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, 'Invalid email format'

    return True, ''


def validate_password_strength(password):
    """Validate password strength requirements.

    Requires:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit

    Args:
        password: The password string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not password or not isinstance(password, str):
        return False, 'Password is required'

    if len(password) < 8:
        return False, 'Password must be at least 8 characters'

    if len(password) > 128:
        return False, 'Password must be at most 128 characters'

    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'

    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'

    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one digit'

    return True, ''


def validate_tool_flags(flags):
    """Validate tool flags to prevent shell metacharacter injection.

    Args:
        flags: The tool flags string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not flags:
        return True, ''  # Empty flags are OK

    if not isinstance(flags, str):
        return False, 'Tool flags must be a string'

    # Check for shell metacharacters that could be dangerous
    dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in flags:
            return False, f'Tool flags contain disallowed character: {char!r}'

    return True, ''


def validate_timeout(timeout):
    """Validate a scan timeout value.

    Args:
        timeout: The timeout value to validate (int or string).

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if timeout is None:
        return True, ''  # None means use default

    try:
        timeout_int = int(timeout)
    except (ValueError, TypeError):
        return False, 'Timeout must be a number'

    if timeout_int < 60:
        return False, 'Timeout must be at least 60 seconds'

    if timeout_int > 7200:
        return False, 'Timeout must be at most 7200 seconds (2 hours)'

    return True, ''


def validate_json_tool_settings(settings_str):
    """Validate tool settings string as valid JSON with safe structure.

    Args:
        settings_str: The settings string to validate.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    if not settings_str:
        return True, ''  # Empty settings are OK

    if not isinstance(settings_str, str):
        return False, 'Settings must be a string'

    try:
        parsed = json.loads(settings_str)
    except json.JSONDecodeError:
        return False, 'Settings must be valid JSON'

    # Must be a dict/object at the top level
    if not isinstance(parsed, dict):
        return False, 'Settings must be a JSON object'

    # Check for overly deep nesting (potential DoS)
    def _check_depth(obj, current_depth=0, max_depth=10):
        if current_depth > max_depth:
            return False
        if isinstance(obj, dict):
            return all(
                _check_depth(v, current_depth + 1, max_depth)
                for v in obj.values()
            )
        if isinstance(obj, list):
            return all(
                _check_depth(v, current_depth + 1, max_depth)
                for v in obj
            )
        return True

    if not _check_depth(parsed):
        return False, 'Settings JSON nesting is too deep'

    # Check for excessive keys (potential DoS)
    def _count_keys(obj, count=0, max_keys=500):
        if count > max_keys:
            return max_keys + 1
        if isinstance(obj, dict):
            for v in obj.values():
                count = _count_keys(v, count + len(obj), max_keys)
                if count > max_keys:
                    return max_keys + 1
        elif isinstance(obj, list):
            for v in obj:
                count = _count_keys(v, count, max_keys)
                if count > max_keys:
                    return max_keys + 1
        return count

    if _count_keys(parsed) > 500:
        return False, 'Settings JSON has too many keys'

    return True, ''
