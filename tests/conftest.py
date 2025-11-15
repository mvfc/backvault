"""Pytest configuration and fixtures for BackVault tests."""

import sys
import os
import tempfile
import logging
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture(scope="session", autouse=True)
def patch_logging():
    """
    Patch logging.FileHandler to redirect /var/log paths to temp directory.
    This prevents permission errors when testing outside Docker.
    """
    # Create temp directory for logs
    temp_log_dir = tempfile.mkdtemp()
    temp_log_file = os.path.join(temp_log_dir, "test.log")

    # Save original FileHandler
    original_file_handler = logging.FileHandler

    class PatchedFileHandler(original_file_handler):
        """FileHandler that redirects /var/log/* paths to temp directory."""

        def __init__(self, filename, *args, **kwargs):
            if "/var/log" in filename:
                filename = temp_log_file
            super().__init__(filename, *args, **kwargs)

    # Apply patch
    logging.FileHandler = PatchedFileHandler

    yield temp_log_dir

    # Restore original FileHandler
    logging.FileHandler = original_file_handler

    # Cleanup temp directory
    import shutil

    if os.path.exists(temp_log_dir):
        shutil.rmtree(temp_log_dir)


@pytest.fixture
def test_password():
    """Fixture providing a test password."""
    return "TestPassword123!SecureVault"


@pytest.fixture
def test_data():
    """Fixture providing test data."""
    return b"This is a test vault backup with sensitive data! Include special chars: \xe2\x9c\x93"
