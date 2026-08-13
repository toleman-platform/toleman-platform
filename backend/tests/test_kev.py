import pytest
import httpx

import app.core.kev as kev_module
from app.core.kev import fetch_kev_cve_set


@pytest.fixture(autouse=True)
def _reset_kev_cache():
    """The in-process cache (added to stop re-downloading the multi-MB KEV
    catalog on every ingestion call) persists across calls within a process,
    including across tests in the same pytest run - reset it so each test's
    mocked httpx.get is what actually gets exercised, not a previous test's
    cached result."""
    kev_module._cache["cve_ids"] = None
    kev_module._cache["fetched_at"] = 0.0
    yield
    kev_module._cache["cve_ids"] = None
    kev_module._cache["fetched_at"] = 0.0


def _mock_response(status_code=200, json_data=None):
    request = httpx.Request("GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return httpx.Response(status_code, json=json_data, request=request)


def test_successful_parse_of_realistic_response_shape(mocker):
    payload = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.12",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
            },
            {
                "cveID": "CVE-2022-12345",
                "vendorProject": "Example",
                "product": "Example Product",
                "vulnerabilityName": "Example Vulnerability",
                "dateAdded": "2022-01-01",
            },
        ],
    }
    mocker.patch("httpx.get", return_value=_mock_response(200, payload))

    cve_set = fetch_kev_cve_set()

    assert cve_set == {"CVE-2021-44228", "CVE-2022-12345"}


def test_network_failure_returns_empty_set(mocker):
    mocker.patch("httpx.get", side_effect=httpx.ConnectTimeout("timed out"))

    cve_set = fetch_kev_cve_set()

    assert cve_set == set()


def test_non_200_response_returns_empty_set(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(503, {}))

    cve_set = fetch_kev_cve_set()

    assert cve_set == set()


def test_empty_catalog_returns_empty_set(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(200, {"vulnerabilities": []}))

    cve_set = fetch_kev_cve_set()

    assert cve_set == set()


def test_second_call_within_ttl_does_not_refetch(mocker):
    mock_get = mocker.patch("httpx.get", return_value=_mock_response(200, {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}))

    first = fetch_kev_cve_set()
    second = fetch_kev_cve_set()

    assert first == second == {"CVE-2021-44228"}
    assert mock_get.call_count == 1


def test_failure_after_a_good_fetch_falls_back_to_stale_cache_not_empty(mocker):
    """A transient CISA outage shouldn't wipe out a KEV list we already know
    to be correct - better to scan against slightly-stale KEV data than none."""
    mocker.patch("httpx.get", return_value=_mock_response(200, {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}))
    first = fetch_kev_cve_set()
    assert first == {"CVE-2021-44228"}

    # Force the cache to look expired, then fail the "refetch".
    kev_module._cache["fetched_at"] = 0.0
    mocker.patch("httpx.get", side_effect=httpx.ConnectTimeout("timed out"))

    second = fetch_kev_cve_set()
    assert second == {"CVE-2021-44228"}
