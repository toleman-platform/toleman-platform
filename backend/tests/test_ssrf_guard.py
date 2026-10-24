import pytest

from app.core.ssrf_guard import UnsafeScanHostError, assert_safe_scan_host


def test_cloud_metadata_ip_literal_is_blocked():
    with pytest.raises(UnsafeScanHostError):
        assert_safe_scan_host("http://169.254.169.254/latest/meta-data/iam/security-credentials/")


def test_hostname_resolution_is_deliberately_not_performed():
    """metadata.google.internal resolves to the exact blocked IP above on a
    real GCP host, but this module checks IP literals only (see its
    docstring for why -- resolving would make this check's result depend
    on live DNS, which a sandboxed test/CI runner may not have). A literal
    IP is what actually gets typed into api_base_url in practice; this
    documents the gap rather than hiding it."""
    assert_safe_scan_host("http://metadata.google.internal/") is None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/admin",
        "http://127.1/",  # inet_aton shorthand for 127.0.0.1
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://169.254.169.254/",
        "http://localhost/",
        "http://foo.localhost/",
    ],
)
def test_loopback_link_local_and_unspecified_are_blocked(url):
    with pytest.raises(UnsafeScanHostError):
        assert_safe_scan_host(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/",
        "http://10.0.0.5/",  # RFC 1918 is deliberately allowed: admin-authorized
        "http://192.168.1.50:8080/",  # on-prem scanning is an intended capability,
        "http://172.16.3.4/",  # see module docstring.
    ],
)
def test_public_and_rfc1918_hosts_are_allowed(url):
    assert_safe_scan_host(url)  # does not raise
