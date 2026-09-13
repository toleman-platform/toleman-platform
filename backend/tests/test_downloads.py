"""Tests for app.core.downloads: Content-Disposition construction (#302).

Every downloadable artifact in this codebase names itself after data the
user controls (a Target's name, a branch), so this module is the one place
that decides whether a repo can steer an HTTP header, crash a download on
latin-1 encoding, or lose its file extension to a length cap. Unit-tested
directly rather than only through the export endpoints, because the rules
it encodes (what counts as an extension, what survives truncation) are not
obvious from any single call site.
"""
import pytest

from app.core.downloads import MAX_FILENAME_LENGTH, ascii_filename, attachment_disposition


def _ascii_param(disposition: str) -> str:
    return disposition.split('filename="')[1].split('"')[0]


def _extended_param(disposition: str) -> str:
    return disposition.split("filename*=UTF-8''")[1]


# --- header safety ---------------------------------------------------------

@pytest.mark.parametrize(
    "name",
    [
        'quote".csv',
        "semi;colon.csv",
        "new\nline.csv",
        "carriage\rreturn.csv",
        "../../etc/passwd.csv",
        "back\\slash.csv",
        'eq"; filename=owned.csv',
        "日本語.csv",
        "café.csv",
        "....csv",
        "",
    ],
)
def test_disposition_is_always_a_safe_header(name):
    disposition = attachment_disposition(name)
    # Exactly the two quotes delimiting the ASCII parameter: nothing in the
    # name can close it early and start a parameter of its own.
    assert disposition.count('"') == 2
    assert "\n" not in disposition and "\r" not in disposition
    # HTTP headers are latin-1; this is what used to 500 the SBOM exports.
    disposition.encode("latin-1")
    assert disposition.startswith("attachment; filename=")


def test_injected_filename_parameter_never_materialises():
    disposition = attachment_disposition('eq"; filename=owned.csv')
    assert "filename=owned.csv" not in disposition


def test_ascii_fallback_never_empty():
    assert ascii_filename("") == "download"
    assert ascii_filename("日本語") == "download"
    assert ascii_filename("---") == "download"


# --- the real name survives ------------------------------------------------

def test_non_ascii_name_is_preserved_in_the_extended_parameter():
    """Sanitising to ASCII alone is safe but lossy: every non-Latin repo
    would file under one shared placeholder. RFC 6266 sends both."""
    disposition = attachment_disposition("日本語.csv")
    assert _extended_param(disposition) == "%E6%97%A5%E6%9C%AC%E8%AA%9E.csv"
    assert _ascii_param(disposition).endswith(".csv")


def test_two_different_non_ascii_names_do_not_collide():
    a = _extended_param(attachment_disposition("日本語.csv"))
    b = _extended_param(attachment_disposition("中文.csv"))
    assert a != b


# --- truncation keeps the extension ----------------------------------------

@pytest.mark.parametrize("extension", [".csv", ".pdf", ".json", ".spdx.json", ".cdx.json"])
def test_a_long_name_keeps_its_extension_in_both_parameters(extension):
    """A plain slice at the cap pushed the extension off the end and the
    file saved extension-less. The compound-extension SBOM paths were the
    most exposed, spending the most characters on the suffix."""
    disposition = attachment_disposition("r" * 300 + extension)
    assert _ascii_param(disposition).endswith(extension)
    assert _extended_param(disposition).endswith(extension)
    assert len(_ascii_param(disposition)) <= MAX_FILENAME_LENGTH


def test_a_compound_extension_is_not_shortened_to_its_last_segment():
    """Truncating ".spdx.json" to ".json" would relabel an SPDX document as
    a generic one."""
    assert _ascii_param(attachment_disposition("sbom-" + "r" * 300 + ".spdx.json")).endswith(".spdx.json")


def test_a_trailing_date_is_not_mistaken_for_an_extension():
    """Extension segments must start with a letter, so the date slug in
    "...-20260913.csv" stays in the stem where truncation can eat it,
    instead of being protected as though it were part of the suffix."""
    name = "toleman-posture-report-" + "r" * 300 + "-20260913.csv"
    result = ascii_filename(name)
    assert result.endswith(".csv")
    assert "20260913" not in result


def test_a_short_name_is_left_alone():
    assert ascii_filename("toleman-posture-report-repo-20260913.csv") == (
        "toleman-posture-report-repo-20260913.csv"
    )


def test_narrowing_markers_survive_a_normal_length_name():
    """The filtered / NofM-sections markers are the point of the report
    filename; nothing here may quietly drop them."""
    name = "toleman-posture-report-repo-filtered-2of6-sections-20260913.csv"
    assert ascii_filename(name) == name
