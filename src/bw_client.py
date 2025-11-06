import os
import subprocess
import json
import logging
from typing import Any
from sys import stdout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/cron.log"),
        logging.StreamHandler(stdout)
    ]
)

logger = logging.getLogger(__name__)

class BitwardenError(Exception):
    """Base exception for Bitwarden wrapper."""

    pass


class BitwardenClient:
    def __init__(
        self,
        bw_cmd: str = "bw",
        session: str | None = None,
        server: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_api_key: bool = True,
    ):
        """
        Initialize Bitwarden client wrapper.

        :param bw_cmd: Path to bw CLI command (default "bw")
        :param session: Existing BW_SESSION token (optional)
        :param server: Bitwarden server URL (optional, Vaultwarden compatible)
        :param client_id: Client ID for API key login (optional)
        :param client_secret: Client Secret for API key login (optional)
        :param use_api_key: Whether to use API key login if client_id and client_secret are provided (Default to True)
        """
        self.bw_cmd = bw_cmd
        self.session = session
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_api_key = (
            use_api_key and client_id is not None and client_secret is not None
        )
        if server:
            logger.debug(f"Configuring BW server: {server}")
            env = os.environ.copy()  # do not add BW_SESSION
            try:
                subprocess.run(
                    [self.bw_cmd, "config", "server", server],
                    text=True,
                    capture_output=True,
                    check=True,
                    env=env,
                    preexec_fn=None,  # Disable process group creation
                )
            except CalledProcessError:
                continue
            except:
                try:
                    self.logout()
                except:
                    pass
                raise BitwardenError(f"Failed to configure BW server to {server}")

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def _run(self, cmd: list[str], capture_json: bool = True) -> Any:
        """
        Run a bw CLI command safely.
        :param cmd: list of arguments, e.g., ["list", "items"]
        :param capture_json: parse stdout as JSON if True
        """
        env = os.environ.copy()
        if self.session:
            env["BW_SESSION"] = self.session
        full_cmd = [self.bw_cmd] + cmd
        logger.debug(f"Running command: {' '.join(full_cmd)}")
        result = subprocess.run(
            full_cmd,
            text=True,
            capture_output=True,
            check=True,
            env=env,
            preexec_fn=None,  # Disable process group creation
        )

        if result.returncode != 0:
            logger.error(f"Bitwarden CLI error: {result.stderr.strip()}")
            raise BitwardenError(result.stderr.strip())

        output = result.stdout.strip()
        if capture_json:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON output: {output}")
                raise BitwardenError("Failed to parse JSON output")
        else:
            return output

    # -------------------------------
    # Core API methods
    # -------------------------------
    def logout(self) -> None:
        """Logout and clear session"""
        self._run(["logout"], capture_json=False)
        self.session = None
        logger.info("Logged out successfully")

    def status(self) -> dict[str, Any]:
        """Return current session status"""
        return self._run(["status"])

    def login(
        self, email: str | None = None, password: str | None = None, raw: bool = True
    ) -> str:
        """
        Login with email/password or API key.
        Returns session key if raw=True.
        """
        if self.use_api_key:
            logger.info("Logging in via API key")

            # Ensure env vars are set so bw login --apikey is non-interactive
            env = os.environ.copy()
            env["BW_CLIENTID"] = self.client_id
            env["BW_CLIENTSECRET"] = self.client_secret

            cmd = [self.bw_cmd, "login", "--apikey"]

            # Run CLI
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, env=env
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Bitwarden CLI login failed: {e.stderr.strip()}")
                try:
                    self.logout()
                except:
                    pass
                raise BitwardenError(e.stderr.strip())

            self.session = result.stdout.strip()
            logger.info("Logged in successfully")

        else:
            logger.info("Logging in via email/password")
            cmd = ["login", email]
            if password:
                cmd += ["--password", password]
            if raw:
                cmd.append("--raw")
            self.session = self._run(cmd, capture_json=False)
            logger.info("Logged in successfully")

        return self.session

    def unlock(self, password: str) -> str:
        """
        Unlock vault with master password or API key secret.
        Returns session token.
        """
        env = os.environ.copy()
        env["BW_SESSION"] = self.session

        cmd = [self.bw_cmd, "unlock", password, "--raw"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, env=env
            )
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Bitwarden CLI unlock failed: {e.stderr.strip()}. Logging out."
            )
            self.logout()
            raise BitwardenError(e.stderr.strip())

        self.session = result.stdout.strip()
        logger.info("Vault unlocked successfully")
        return self.session
