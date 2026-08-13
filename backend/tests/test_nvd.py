import httpx

from app.core.nvd import fetch_nvd_cve


def _mock_response(status_code=200, json_data=None):
    request = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    return httpx.Response(status_code, json=json_data, request=request)


_REALISTIC_PAYLOAD = {
    "resultsPerPage": 1,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-28483",
                "descriptions": [
                    {"lang": "en", "value": "This affects all versions of package github.com/gin-gonic/gin."},
                    {"lang": "es", "value": "Esto afecta a todas las versiones."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                                "baseScore": 7.1,
                            }
                        }
                    ],
                    "cvssMetricV2": [{"cvssData": {"vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:N", "baseScore": 5.8}}],
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-444"}]},
                    {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
                ],
                "references": [
                    {"url": "https://github.com/gin-gonic/gin/pull/2474"},
                    {"url": "https://snyk.io/vuln/SNYK-1"},
                ],
            }
        }
    ],
}


def test_successful_parse_of_realistic_response_shape(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(200, _REALISTIC_PAYLOAD))

    result = fetch_nvd_cve("CVE-2020-28483")

    assert result is not None
    assert result["description"] == "This affects all versions of package github.com/gin-gonic/gin."
    assert result["cvss_score"] == 7.1
    assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
    # Real "NVD-CWE-noinfo" placeholder must not be surfaced as a fabricated CWE.
    assert result["cwe_ids"] == ["CWE-444"]
    assert result["references"] == ["https://github.com/gin-gonic/gin/pull/2474", "https://snyk.io/vuln/SNYK-1"]


def test_cve_not_found_returns_none(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(200, {"resultsPerPage": 0, "vulnerabilities": []}))

    assert fetch_nvd_cve("CVE-9999-99999") is None


def test_network_failure_returns_none(mocker):
    mocker.patch("httpx.get", side_effect=httpx.ConnectTimeout("timed out"))

    assert fetch_nvd_cve("CVE-2020-28483") is None


def test_non_200_response_returns_none(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(403, {}))

    assert fetch_nvd_cve("CVE-2020-28483") is None


def test_no_cvss_metrics_leaves_score_and_vector_none(mocker):
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "d"}], "metrics": {}, "references": []}}
        ]
    }
    mocker.patch("httpx.get", return_value=_mock_response(200, payload))

    result = fetch_nvd_cve("CVE-1")

    assert result["cvss_score"] is None
    assert result["cvss_vector"] is None
    assert result["cwe_ids"] == []
