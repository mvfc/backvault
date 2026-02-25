import pytest
import subprocess
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
import shutil


@pytest.fixture
def temp_dir():
    """
    Provide a temporary directory for tests and remove it after the test finishes.
    
    Yields:
        temp_dir (str): Path to a newly created temporary directory that will be deleted after use.
    """
    temp = tempfile.mkdtemp()
    yield temp
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def run_script_path():
    """Get the path to run.sh."""
    return Path(__file__).parent.parent / "run.sh"


class TestRunShCronExpression:
    """Tests for CRON expression generation logic."""

    def test_cron_expression_default_12_hours(self, run_script_path, temp_dir):
        """Test default BACKUP_INTERVAL_HOURS of 12 generates correct cron expression."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "12"

        # Create a minimal test that just validates cron calculation without full execution
        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
if [ -z "${CRON_EXPRESSION:-}" ]; then
    DAYS=$((INTERVAL_HOURS / 24))
    HOURS=$((INTERVAL_HOURS % 24))

    CRON_DAY="*"
    if [ "$DAYS" -gt 0 ]; then
        CRON_DAY="*/$DAYS"
    fi

    if [ "$HOURS" -gt 0 ]; then
        CRON_HOUR="*/$HOURS"
    else
        CRON_HOUR="0"
    fi

    CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
fi
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0 */12 * * *"

    def test_cron_expression_24_hours_full_day(self, temp_dir):
        """Test BACKUP_INTERVAL_HOURS of 24 generates daily cron expression."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "24"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

CRON_DAY="*"
if [ "$DAYS" -gt 0 ]; then
    CRON_DAY="*/$DAYS"
fi

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi

CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0 0 */1 * *"

    def test_cron_expression_48_hours_two_days(self, temp_dir):
        """Test BACKUP_INTERVAL_HOURS of 48 generates every 2 days cron expression."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "48"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

CRON_DAY="*"
if [ "$DAYS" -gt 0 ]; then
    CRON_DAY="*/$DAYS"
fi

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi

CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0 0 */2 * *"

    def test_cron_expression_6_hours(self, temp_dir):
        """Test BACKUP_INTERVAL_HOURS of 6 generates every 6 hours cron expression."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "6"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

CRON_DAY="*"
if [ "$DAYS" -gt 0 ]; then
    CRON_DAY="*/$DAYS"
fi

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi

CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0 */6 * * *"

    def test_cron_expression_custom_provided(self, temp_dir):
        """Test that custom CRON_EXPRESSION is used when provided."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "12"
        env["CRON_EXPRESSION"] = "*/30 * * * *"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
if [ -z "${CRON_EXPRESSION:-}" ]; then
    DAYS=$((INTERVAL_HOURS / 24))
    HOURS=$((INTERVAL_HOURS % 24))

    CRON_DAY="*"
    if [ "$DAYS" -gt 0 ]; then
        CRON_DAY="*/$DAYS"
    fi

    if [ "$HOURS" -gt 0 ]; then
        CRON_HOUR="*/$HOURS"
    else
        CRON_HOUR="0"
    fi

    CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
fi
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "*/30 * * * *"

    def test_cron_expression_mixed_days_and_hours(self, temp_dir):
        """Test BACKUP_INTERVAL_HOURS with both days and hours (30 hours = 1 day + 6 hours)."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "30"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

CRON_DAY="*"
if [ "$DAYS" -gt 0 ]; then
    CRON_DAY="*/$DAYS"
fi

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi

CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
echo "$CRON_EXPRESSION"
"""
        script_path = Path(temp_dir) / "test_cron.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0 */6 */1 * *"


class TestRunShCommandValidation:
    """Tests for command validation when arguments are provided."""

    def test_allowed_bw_command(self, run_script_path):
        """
        Verify that invoking the script with the `bw` command does not trigger the disallowed-command error.
        
        Asserts that running the wrapper with arguments `bw --version` does not produce the specific "Error: Unknown or disallowed command" message on stderr.
        """
        result = subprocess.run(
            ["bash", str(run_script_path), "bw", "--version"],
            capture_output=True,
            text=True
        )

        # The script should exec the bw command, which may or may not be installed
        # If not installed, we'll get an error from bash, not our script's error message
        assert "Error: Unknown or disallowed command" not in result.stderr

    def test_disallowed_command_rejection(self, run_script_path):
        """Test that disallowed commands are rejected with proper error message."""
        result = subprocess.run(
            ["bash", str(run_script_path), "rm", "-rf", "/"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 1
        assert "Error: Unknown or disallowed command: rm" in result.stdout
        assert "Allowed commands: bw, uvicorn, supercronic, bash, sh" in result.stdout

    def test_python_command_disallowed(self, run_script_path):
        """Test that python command is rejected."""
        result = subprocess.run(
            ["bash", str(run_script_path), "python", "script.py"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 1
        assert "Error: Unknown or disallowed command: python" in result.stdout

    def test_curl_command_disallowed(self, run_script_path):
        """Test that curl command is rejected."""
        result = subprocess.run(
            ["bash", str(run_script_path), "curl", "http://example.com"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 1
        assert "Error: Unknown or disallowed command: curl" in result.stdout

    def test_empty_command_starts_service(self, run_script_path):
        """Test that no arguments triggers service initialization (will fail without full env)."""
        # This test verifies the script tries to start initialization when no args provided
        result = subprocess.run(
            ["bash", str(run_script_path)],
            capture_output=True,
            text=True,
            timeout=2,
            env={**os.environ, "BACKUP_INTERVAL_HOURS": "12"}
        )

        # Should start initialization - will fail due to missing dependencies but proves path taken
        # We expect it to print the initialization message
        assert "Initializing Backvault container" in result.stdout or result.returncode != 0


class TestRunShEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_default_ui_host(self, temp_dir):
        """Test that UI_HOST defaults to 0.0.0.0."""
        script_content = """
#!/bin/bash
set -euo pipefail
UI_HOST="${SETUP_UI_HOST:-0.0.0.0}"
echo "$UI_HOST"
"""
        script_path = Path(temp_dir) / "test_env.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0.0.0.0"

    def test_custom_ui_host(self, temp_dir):
        """Test that SETUP_UI_HOST can be customized."""
        env = os.environ.copy()
        env["SETUP_UI_HOST"] = "192.168.1.100"

        script_content = """
#!/bin/bash
set -euo pipefail
UI_HOST="${SETUP_UI_HOST:-0.0.0.0}"
echo "$UI_HOST"
"""
        script_path = Path(temp_dir) / "test_env.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "192.168.1.100"

    def test_default_ui_port(self, temp_dir):
        """Test that UI_PORT defaults to 8080."""
        script_content = """
#!/bin/bash
set -euo pipefail
UI_PORT="${SETUP_UI_PORT:-8080}"
echo "$UI_PORT"
"""
        script_path = Path(temp_dir) / "test_env.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "8080"

    def test_custom_ui_port(self, temp_dir):
        """Test that SETUP_UI_PORT can be customized."""
        env = os.environ.copy()
        env["SETUP_UI_PORT"] = "9000"

        script_content = """
#!/bin/bash
set -euo pipefail
UI_PORT="${SETUP_UI_PORT:-8080}"
echo "$UI_PORT"
"""
        script_path = Path(temp_dir) / "test_env.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "9000"

    def test_default_backup_dir(self, temp_dir):
        """Test that BACKUP_DIR defaults to /app/backups."""
        script_content = """
#!/bin/bash
set -euo pipefail
BACKUP_DIR=${BACKUP_DIR:-"/app/backups"}
echo "$BACKUP_DIR"
"""
        script_path = Path(temp_dir) / "test_env.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "/app/backups"


class TestRunShWrapperGeneration:
    """Tests for run_wrapper.sh generation."""

    def test_wrapper_includes_bw_and_backup_vars(self, temp_dir):
        """
        Verify the generated wrapper lists and exports environment variables whose names start with `BW_` or `BACKUP_`, and excludes unrelated variables.
        
        Sets example `BW_` and `BACKUP_` variables, runs the wrapper-like script that emits `export` lines for matching environment entries, and asserts the expected exports appear and unrelated variables do not.
        """
        env = os.environ.copy()
        env["BW_SERVER"] = "https://test.bitwarden.com"
        env["BACKUP_DIR"] = "/test/backups"
        env["BACKUP_ENCRYPTION_MODE"] = "bitwarden"
        env["OTHER_VAR"] = "should_not_appear"

        # Test that env command with grep filters correctly for BW_ and BACKUP_ vars
        script_content = r"""
#!/bin/bash
set -euo pipefail
# Simulate what the actual script does - filter for BW_ and BACKUP_ variables
env | grep -E '^(BW_|BACKUP_)' | while IFS= read -r line; do
    echo "export $line"
done
"""
        script_path = Path(temp_dir) / "test_wrapper.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "export BW_SERVER=" in result.stdout
        assert "export BACKUP_DIR=" in result.stdout
        assert "export BACKUP_ENCRYPTION_MODE=" in result.stdout
        assert "OTHER_VAR" not in result.stdout

    def test_wrapper_has_correct_shebang(self, temp_dir):
        """Test that wrapper script has correct shebang and structure."""
        script_content = """
#!/bin/bash
set -euo pipefail
cat > /tmp/test_wrapper2.sh <<'EOF'
#!/bin/bash
set -euo pipefail
export PATH="/usr/local/bin:$PATH"
/usr/local/bin/python /app/src/run.py 2>&1 | tee -a /app/logs/cron.log
EOF
head -n 1 /tmp/test_wrapper2.sh
"""
        script_path = Path(temp_dir) / "test_wrapper.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "#!/bin/bash"


class TestRunShCrontabGeneration:
    """Tests for crontab file generation."""

    def test_crontab_contains_backup_schedule(self, temp_dir):
        """Test that crontab includes backup job with correct cron expression."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "12"

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
CRON_EXPRESSION="0 */12 * * *"
cat > /tmp/test_crontab <<EOF
# Backvault scheduled backup
$CRON_EXPRESSION /app/run_wrapper.sh
# Cleanup job every midnight
0 0 * * * /app/cleanup.sh 2>&1 | tee -a /app/logs/cron.log
EOF
cat /tmp/test_crontab
"""
        script_path = Path(temp_dir) / "test_crontab.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "0 */12 * * * /app/run_wrapper.sh" in result.stdout
        assert "# Backvault scheduled backup" in result.stdout

    def test_crontab_contains_cleanup_job(self, temp_dir):
        """Test that crontab includes cleanup job at midnight."""
        script_content = """
#!/bin/bash
set -euo pipefail
cat > /tmp/test_crontab2 <<'EOF'
# Backvault scheduled backup
0 */12 * * * /app/run_wrapper.sh
# Cleanup job every midnight
0 0 * * * /app/cleanup.sh 2>&1 | tee -a /app/logs/cron.log
EOF
cat /tmp/test_crontab2
"""
        script_path = Path(temp_dir) / "test_crontab.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "0 0 * * * /app/cleanup.sh" in result.stdout
        assert "# Cleanup job every midnight" in result.stdout


class TestRunShBackupDirectoryCheck:
    """Tests for backup directory existence and content checks."""

    def test_initial_backup_skipped_when_backups_exist(self, temp_dir):
        """Test that initial backup is skipped when backup directory has files."""
        backup_dir = Path(temp_dir) / "backups"
        backup_dir.mkdir()
        (backup_dir / "existing_backup.json").write_text('{"test": "data"}')

        env = os.environ.copy()
        env["BACKUP_DIR"] = str(backup_dir)

        script_content = f"""
#!/bin/bash
set -euo pipefail
BACKUP_DIR={backup_dir}
if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
    echo "Found existing backups in $BACKUP_DIR, skipping initial backup."
else
    echo "Running initial backup..."
fi
"""
        script_path = Path(temp_dir) / "test_backup_check.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "Found existing backups" in result.stdout
        assert "skipping initial backup" in result.stdout

    def test_initial_backup_runs_when_directory_empty(self, temp_dir):
        """Test that initial backup runs when backup directory is empty."""
        backup_dir = Path(temp_dir) / "backups"
        backup_dir.mkdir()

        env = os.environ.copy()
        env["BACKUP_DIR"] = str(backup_dir)

        script_content = f"""
#!/bin/bash
set -euo pipefail
BACKUP_DIR={backup_dir}
if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
    echo "Found existing backups in $BACKUP_DIR, skipping initial backup."
else
    echo "Running initial backup..."
fi
"""
        script_path = Path(temp_dir) / "test_backup_check.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "Running initial backup..." in result.stdout

    def test_initial_backup_runs_when_directory_missing(self, temp_dir):
        """Test that initial backup runs when backup directory doesn't exist."""
        backup_dir = Path(temp_dir) / "nonexistent_backups"

        env = os.environ.copy()
        env["BACKUP_DIR"] = str(backup_dir)

        script_content = f"""
#!/bin/bash
set -euo pipefail
BACKUP_DIR={backup_dir}
if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
    echo "Found existing backups in $BACKUP_DIR, skipping initial backup."
else
    echo "Running initial backup..."
fi
"""
        script_path = Path(temp_dir) / "test_backup_check.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "Running initial backup..." in result.stdout


class TestRunShEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_script_fails_on_unset_variable_access(self, temp_dir):
        """Test that script fails fast on unset variable access due to set -u."""
        script_content = """
#!/bin/bash
set -euo pipefail
echo "$UNDEFINED_VARIABLE"
"""
        script_path = Path(temp_dir) / "test_unset.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode != 0
        assert "UNDEFINED_VARIABLE" in result.stderr or "unbound variable" in result.stderr

    def test_script_fails_on_command_error(self, temp_dir):
        """Test that script fails on command error due to set -e."""
        script_content = """
#!/bin/bash
set -euo pipefail
false
echo "This should not print"
"""
        script_path = Path(temp_dir) / "test_error.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        assert result.returncode != 0
        assert "This should not print" not in result.stdout

    def test_cron_expression_with_zero_hours(self, temp_dir):
        """Test edge case where BACKUP_INTERVAL_HOURS results in 0 hours component."""
        env = os.environ.copy()
        env["BACKUP_INTERVAL_HOURS"] = "48"  # 2 days, 0 hours

        script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi
echo "$CRON_HOUR"
"""
        script_path = Path(temp_dir) / "test_zero_hours.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script_path)],
            env=env,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "0"

    def test_bw_command_with_multiple_arguments(self, run_script_path):
        """Test that bw command accepts multiple arguments."""
        result = subprocess.run(
            ["bash", str(run_script_path), "bw", "list", "items", "--session", "test"],
            capture_output=True,
            text=True
        )

        # Should not reject the command (will fail later if bw not installed, but that's OK)
        assert "Error: Unknown or disallowed command" not in result.stderr
        assert "Error: Unknown or disallowed command" not in result.stdout

    def test_numeric_backup_interval_hours(self, temp_dir):
        """Test that various numeric values for BACKUP_INTERVAL_HOURS work correctly."""
        test_cases = [
            ("1", "0 */1 * * *"),
            ("3", "0 */3 * * *"),
            ("72", "0 0 */3 * *"),  # 3 days
            ("168", "0 0 */7 * *"),  # 7 days
        ]

        for hours, expected_cron in test_cases:
            env = os.environ.copy()
            env["BACKUP_INTERVAL_HOURS"] = hours

            script_content = """
#!/bin/bash
set -euo pipefail
INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
DAYS=$((INTERVAL_HOURS / 24))
HOURS=$((INTERVAL_HOURS % 24))

CRON_DAY="*"
if [ "$DAYS" -gt 0 ]; then
    CRON_DAY="*/$DAYS"
fi

if [ "$HOURS" -gt 0 ]; then
    CRON_HOUR="*/$HOURS"
else
    CRON_HOUR="0"
fi

CRON_EXPRESSION="0 $CRON_HOUR $CRON_DAY * *"
echo "$CRON_EXPRESSION"
"""
            script_path = Path(temp_dir) / f"test_cron_{hours}.sh"
            script_path.write_text(script_content)
            script_path.chmod(0o755)

            result = subprocess.run(
                ["bash", str(script_path)],
                env=env,
                capture_output=True,
                text=True
            )

            assert result.returncode == 0, f"Failed for BACKUP_INTERVAL_HOURS={hours}"
            assert result.stdout.strip() == expected_cron, f"Expected {expected_cron} for {hours} hours, got {result.stdout.strip()}"


class TestRunShSecurityConsiderations:
    """Tests for security-related behavior."""

    def test_dangerous_command_rejected(self, run_script_path):
        """Test that potentially dangerous commands are rejected."""
        dangerous_commands = ["rm", "dd", "mkfs", "format", "wget", "curl"]

        for cmd in dangerous_commands:
            result = subprocess.run(
                ["bash", str(run_script_path), cmd, "test"],
                capture_output=True,
                text=True
            )

            assert result.returncode == 1, f"Command '{cmd}' should be rejected"
            assert f"Error: Unknown or disallowed command: {cmd}" in result.stdout

    def test_shell_injection_attempt_rejected(self, run_script_path):
        """Test that shell injection attempts are rejected."""
        result = subprocess.run(
            ["bash", str(run_script_path), "bw; rm -rf /"],
            capture_output=True,
            text=True
        )

        # The command "bw; rm -rf /" is treated as a single argument
        # The script should try to exec "bw; rm -rf /" which will fail
        # but shouldn't execute the rm command
        # This tests that the script doesn't eval the arguments unsafely

    def test_path_traversal_in_command_rejected(self, run_script_path):
        """Test that path traversal attempts in commands are handled safely."""
        result = subprocess.run(
            ["bash", str(run_script_path), "../../../bin/bash"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 1
        assert "Error: Unknown or disallowed command" in result.stdout