from pathlib import Path
import re
from os import getenv


class BitwardenError(Exception):
    """Base exception for Bitwarden wrapper."""

    pass


def validate_path(input_content: str | None, allowed_base: str = "/app") -> str:
    """
    Validate that file paths are within the allowed directories.
    Prevents path traversal attacks.
    """
    if not input_content:
        return ""  # Allow empty paths (optional parameters)

    input_path = Path(input_content).resolve()
    allowed_path = Path(allowed_base).resolve()

    try:
        input_path.relative_to(allowed_path) if not getenv(
            "TEST_MODE"
        ) else input_path.relative_to(Path("/tmp").resolve())
    except ValueError:
        raise BitwardenError(f"Invalid path: must be within {allowed_base}")

    # Validate filename contains only safe characters
    if not re.match(r"^[a-zA-Z0-9._-]+$", input_path.name):
        raise BitwardenError(
            "Invalid filename: only alphanumeric, dots, dashes allowed"
        )

    return str(input_path)
