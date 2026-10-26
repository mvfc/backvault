import json

import pytest

from test_e2e import _is_warning_text, parse_json_output


@pytest.mark.parametrize(
    "warning",
    [
        "DeprecationWarning: deprecated API",
        "Warning: runtime notice",
        "Warning runtime notice",
        "Warning",
        "(node:1234) [DEP0040] DeprecationWarning: punycode",
        "[NOTICE] runtime notice",
        "[WARNING] runtime notice",
        "[ERROR] runtime notice",
        "[DEP0040] DeprecationWarning: punycode",
        "[node:1234] runtime notice",
        "Could not find setting",
        "Saved setting server",
    ],
)
def test_parse_json_output_preserves_supported_warnings(warning):
    assert _is_warning_text(f" \n{warning}\n ")
    assert parse_json_output(f'{warning}\n{{"status": "ok"}}\n{warning}') == {
        "status": "ok"
    }


@pytest.mark.parametrize(
    "message",
    [
        "Operation failed with Warning in the response",
        "Operation emitted DeprecationWarning during export",
        "WarningCount: 1",
        "DeprecationWarningCount: 1",
    ],
)
@pytest.mark.parametrize("position", ["prefix", "suffix"])
def test_parse_json_output_rejects_unrelated_warning_mentions(message, position):
    assert not _is_warning_text(message)
    output = f'{message}\n{{"status": "ok"}}'
    if position == "suffix":
        output = f'{{"status": "ok"}}\n{message}'
    with pytest.raises(json.JSONDecodeError):
        parse_json_output(output)
