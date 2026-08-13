import httpx

from app.core.kev import fetch_kev_cve_set


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
