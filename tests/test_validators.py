"""Validator tests."""
from app.utils.validators import (
    is_valid_domain, is_valid_ip, is_valid_cidr, is_valid_url,
    sanitize_filename, contains_shell_injection, validate_target_value
)


def test_valid_domain():
    assert is_valid_domain('example.com') is True
    assert is_valid_domain('sub.example.com') is True
    assert is_valid_domain('not valid') is False
    assert is_valid_domain('') is False


def test_valid_ip():
    assert is_valid_ip('192.168.1.1') is True
    assert is_valid_ip('::1') is True
    assert is_valid_ip('not an ip') is False


def test_valid_cidr():
    assert is_valid_cidr('192.168.1.0/24') is True
    assert is_valid_cidr('not cidr') is False


def test_valid_url():
    assert is_valid_url('https://example.com') is True
    assert is_valid_url('http://test.com/path') is True
    assert is_valid_url('not a url') is False


def test_shell_injection_detected():
    assert contains_shell_injection('test; rm -rf /') is True
    assert contains_shell_injection('example.com') is False
    assert contains_shell_injection('test | cat /etc/passwd') is True


def test_sanitize_filename():
    assert sanitize_filename('test file.txt') == 'test_file.txt'
    assert sanitize_filename('normal.txt') == 'normal.txt'


def test_validate_target_value():
    valid, msg = validate_target_value('example.com', 'domain')
    assert valid is True

    valid, msg = validate_target_value('not valid', 'domain')
    assert valid is False

    valid, msg = validate_target_value('', 'domain')
    assert valid is False
