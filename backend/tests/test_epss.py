import httpx
import pytest

from app.core.epss import fetch_epss_scores


def _mock_response(status_code=200, json_data=None):
    request = httpx.Request("GET", "https://api.first.org/data/v1/epss")
    return httpx.Response(status_code, json=json_data, request=request)


def test_successful_parse_of_realistic_response_shape(mocker):
    payload = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 2,
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.94402", "percentile": "0.99980", "date": "2026-08-12"},
            {"cve": "CVE-2022-12345", "epss": "0.03210", "percentile": "0.45000", "date": "2026-08-12"},
        ],
    }
    mocker.patch("httpx.get", return_value=_mock_response(200, payload))

    scores = fetch_epss_scores(["CVE-2021-44228", "CVE-2022-12345"])

    assert scores == {"CVE-2021-44228": 0.94402, "CVE-2022-12345": 0.03210}


def test_network_failure_returns_empty_dict(mocker):
    mocker.patch("httpx.get", side_effect=httpx.ConnectTimeout("timed out"))

    scores = fetch_epss_scores(["CVE-2021-44228"])

    assert scores == {}


def test_non_200_response_returns_empty_dict(mocker):
    mocker.patch("httpx.get", return_value=_mock_response(500, {}))

    scores = fetch_epss_scores(["CVE-2021-44228"])

    assert scores == {}


def test_empty_cve_list_short_circuits_without_network_call(mocker):
    mock_get = mocker.patch("httpx.get")

    scores = fetch_epss_scores([])

    assert scores == {}
    mock_get.assert_not_called()
