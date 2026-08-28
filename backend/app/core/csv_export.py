"""CSV export helper: neutralizes formula/DDE injection (CWE-1236).

A cell beginning with =, +, -, @, tab or CR is read as a formula by Excel,
LibreOffice and Google Sheets when the CSV is opened, and can be used to
exfiltrate data or reach a macro. Toleman's exports (compliance reports,
SBOM CSVs) include names and versions pulled from a scanned repository's own
dependency manifest, which is not trusted input: a dependency deliberately
named e.g. "=cmd|' /C calc'!A0" is enough to reach this without the person
exporting the report doing anything wrong.
"""
import csv
from typing import Any, Iterable, TextIO

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


class SafeCsvWriter:
    """Drop-in replacement for csv.writer: same interface, but every cell is
    passed through _safe_cell before it reaches the underlying writer."""

    def __init__(self, buf: TextIO) -> None:
        self._writer = csv.writer(buf)

    def writerow(self, row: Iterable[Any]) -> None:
        self._writer.writerow([_safe_cell(v) for v in row])


def safe_csv_writer(buf: TextIO) -> SafeCsvWriter:
    return SafeCsvWriter(buf)
