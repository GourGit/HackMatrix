"""Unit tests for URL normalization and SSRF validation."""

import pytest
from app.core.errors import InvalidURLError, UnsafeTargetError
from app.core.safety import is_private_ip, validate_ip_safety
from app.core.url_validator import normalize_url


def test_normalize_valid_urls():
    res = normalize_url("https://example.com/login?ref=1#top")
    assert res.normalized_str == "https://example.com/login?ref=1"
    assert res.scheme == "https"
    assert res.host == "example.com"


def test_reject_userinfo():
    with pytest.raises(InvalidURLError):
        normalize_url("https://user:password@example.com")


def test_reject_invalid_scheme():
    with pytest.raises(InvalidURLError):
        normalize_url("ftp://example.com/file")


def test_ssrf_private_ips():
    private_ips = [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",  # Cloud metadata
        "::1",
    ]
    for ip in private_ips:
        assert is_private_ip(ip) is True
        with pytest.raises(UnsafeTargetError):
            validate_ip_safety(ip)


def test_public_ips_allowed():
    public_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]
    for ip in public_ips:
        assert is_private_ip(ip) is False

