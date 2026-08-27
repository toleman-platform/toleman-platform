import csv
import io

from app.core.csv_export import safe_csv_writer


def _rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def test_formula_prefixes_are_neutralized():
    buf = io.StringIO()
    writer = safe_csv_writer(buf)
    writer.writerow(["=cmd|' /C calc'!A0", "+1+1", "-1+1", "@SUM(1,1)", "\tHYPERLINK", "\rDROP", "normal"])
    row = _rows(buf.getvalue())[0]
    assert row == [
        "'=cmd|' /C calc'!A0",
        "'+1+1",
        "'-1+1",
        "'@SUM(1,1)",
        "'\tHYPERLINK",
        "'\rDROP",
        "normal",
    ]


def test_non_string_and_none_cells_pass_through():
    buf = io.StringIO()
    writer = safe_csv_writer(buf)
    writer.writerow([1, None, 3.5, "plain text"])
    row = _rows(buf.getvalue())[0]
    assert row == ["1", "", "3.5", "plain text"]
