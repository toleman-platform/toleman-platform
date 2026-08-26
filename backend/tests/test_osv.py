import httpx

from app.core.osv import fetch_osv_vuln


def _mock_response(status_code=200, json_data=None):
    request = httpx.Request("GET", "https://api.osv.dev/v1/vulns/CVE-2020-28483")
    return httpx.Response(status_code, json=json_data, request=request)


_REALISTIC_PAYLOAD = {
    "id": "CVE-2020-28483",
    "aliases": ["GHSA-h395-qcrw-5vmq", "GO-2021-0052"],
    "affected": [
        {
            "package": {"name": "github.com/gin-gonic/gin", "ecosystem": "Go"},
            "ranges": [
                {
                    "type": "GIT",
                    "events": [{"introduced": "0"}, {"fixed": "d496f645"}],
                    "database_specific": {"extracted_events": [{"introduced": "0"}, {"fixed": "1.7.0"}]},
                }
            ],
        }
    ],
    "references": [
        {"type": "FIX", "url": "https://github.com/gin-gonic/gin/pull/2474"},
        {"type": "FIX", "url": "https://snyk.io/vuln/SNYK-1"},
    ],
}


def test_successful_parse_of_realistic_response_shape(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(200, _REALISTIC_PAYLOAD))

    result = fetch_osv_vuln("CVE-2020-28483")

    assert result is not None
    assert result["osv_id"] == "CVE-2020-28483"
    # extracted_events (human-readable "1.7.0") preferred over the raw GIT
    # commit-hash event; see test_extracted_events_preferred_... below.
    assert result["fixed_versions"] == [
        {"package": "github.com/gin-gonic/gin", "ecosystem": "Go", "fixed": "1.7.0"}
    ]
    assert result["references"] == ["https://github.com/gin-gonic/gin/pull/2474", "https://snyk.io/vuln/SNYK-1"]


def test_extracted_events_preferred_over_raw_git_commit_hash(mocker):
    """Real-world shape (verified live against CVE-2020-28483 on api.osv.dev):
    CVEs auto-converted from NVD's CPE data express GIT-type ranges whose raw
    "fixed" event is a commit hash. OSV's own database_specific.extracted_events
    carries the human-readable version derived from that commit; prefer it."""
    payload = {
        "id": "CVE-2020-28483",
        "affected": [
            {
                "package": {"name": "github.com/gin-gonic/gin", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "0"}, {"fixed": "d496f64540b6707602de50ab57aeea8ff4080b74"}],
                        "database_specific": {"extracted_events": [{"introduced": "0"}, {"fixed": "1.7.0"}]},
                    }
                ],
            }
        ],
        "references": [],
    }
    mocker.patch("httpx.get", return_value=_mock_response(200, payload))

    result = fetch_osv_vuln("CVE-2020-28483")

    assert result["fixed_versions"] == [{"package": "github.com/gin-gonic/gin", "ecosystem": "Go", "fixed": "1.7.0"}]


def test_cve_not_indexed_by_osv_returns_none(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(404, {}))

    assert fetch_osv_vuln("CVE-9999-99999") is None


def test_network_failure_returns_none(mocker):
    mocker.patch("httpx.get", side_effect=httpx.ConnectTimeout("timed out"))

    assert fetch_osv_vuln("CVE-2020-28483") is None


def test_no_fixed_events_yields_empty_fixed_versions_list(mocker):
    payload = {
        "id": "CVE-2",
        "affected": [{"package": {"name": "pkg", "ecosystem": "PyPI"}, "ranges": [{"events": [{"introduced": "0"}]}]}],
        "references": [],
    }
    mocker.patch("httpx.get", return_value=_mock_response(200, payload))

    result = fetch_osv_vuln("CVE-2")

    assert result["fixed_versions"] == []
