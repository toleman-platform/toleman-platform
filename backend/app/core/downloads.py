"""Content-Disposition construction for file downloads.

Every downloadable artifact in this codebase names itself after data the
user controls -- a Target's name, a branch. Interpolating that straight
into the header has two failure modes, and this module exists because both
were live:

* **Header steering.** A name containing a quote or a semicolon closes the
  `filename="..."` parameter and starts a new one, so a repo could name
  itself into a different downloaded filename.
* **A hard 500.** HTTP headers are latin-1; a repo named ``日本語`` raises
  ``UnicodeEncodeError`` deep inside the ASGI layer, and the download fails
  outright rather than falling back to something plain.

RFC 6266 already solves this: send both parameters. ``filename`` carries an
ASCII-only fallback for anything that cannot read the other, and
``filename*`` (RFC 5987) carries the real, percent-encoded UTF-8 name that
every current browser prefers. Sanitising to ASCII *alone* is safe but
lossy in a way that matters at scale -- ``日本語`` and ``中文`` both collapse
to the same placeholder, so two repos' exports arrive with identical names.
"""
import re
from urllib.parse import quote

# Long enough for a descriptive name, short enough to stay well clear of
# both common filesystem limits (255 bytes) and any server's header cap
# once percent-encoding has tripled a non-ASCII name's length.
MAX_FILENAME_LENGTH = 120

_FALLBACK_STEM = "download"

# A trailing run of one or two extension segments. Each must *start with a
# letter*, which is what keeps a date out of the extension: in
# "report-20260913.csv" the ".20260913" segment is rejected and only ".csv"
# is treated as the extension, while ".spdx.json" and ".cdx.json" -- the two
# compound extensions this codebase actually emits, from the SBOM exports --
# are matched in full. Truncating ".spdx.json" down to ".json" would relabel
# an SPDX document as a generic one.
_EXTENSION_RE = re.compile(r"(?:\.[A-Za-z][A-Za-z0-9]{0,7}){1,2}$")


def _split_extension(filename: str) -> tuple[str, str]:
    match = _EXTENSION_RE.search(filename)
    return (filename[: match.start()], match.group(0)) if match else (filename, "")


def _truncate(filename: str) -> str:
    """Cap the length without eating the extension.

    A plain ``[:MAX]`` slice is wrong here: `Target.name` has no length cap
    anywhere in the schema, so a 90-character repo name pushed the ".csv"
    clean off the end and the file saved extension-less -- with the
    compound-extension SBOM paths the most exposed, since they spend the
    most characters on the suffix. The stem absorbs the truncation and the
    extension is re-appended.
    """
    if len(filename) <= MAX_FILENAME_LENGTH:
        return filename
    stem, extension = _split_extension(filename)
    stem = stem[: max(MAX_FILENAME_LENGTH - len(extension), 1)].rstrip("-. ")
    return (stem or _FALLBACK_STEM) + extension


def ascii_filename(filename: str) -> str:
    """The ASCII-only `filename=` fallback.

    Anything outside ``[A-Za-z0-9._-]`` becomes a hyphen: that set excludes
    every character that could steer the header (quote, semicolon, CR/LF)
    and every path separator, so the result is safe to interpolate between
    quotes without escaping. Runs collapse to a single hyphen so a name made
    entirely of punctuation doesn't yield a row of them.

    Slugified before truncating, not after: slugifying can shorten the name
    (a run of CJK collapses to one hyphen), so measuring first would cut
    more than necessary.
    """
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", filename)
    # Collapse hyphen runs, including ones formed by a stripped segment
    # landing between two existing separators ("a-<CJK>-b" -> "a---b" -> "a-b").
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    slug = _truncate(slug)
    return slug or _FALLBACK_STEM


def attachment_disposition(filename: str) -> str:
    """A complete ``Content-Disposition`` value for `filename`.

    Emits both parameters (see the module docstring). `filename` is the
    *display* name -- pass the real one, non-ASCII included; the ASCII
    fallback is derived here rather than by the caller, so no caller can
    forget to sanitise.
    """
    filename = _truncate(filename)
    fallback = ascii_filename(filename)
    # safe="" percent-encodes everything except RFC 3986's unreserved set,
    # which is a subset of RFC 5987's attr-char -- over-encoding is valid
    # and means quote/semicolon/CR/LF cannot survive into the header.
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
