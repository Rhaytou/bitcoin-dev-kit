"""
core/config.py
==============
Central configuration loader for the Bitcoin Dev Kit.

Reads all environment variables from the project root .env file using
python-dotenv. Every module in the project imports from here — no
credentials or config values are ever hardcoded anywhere else.

Usage:
    from core.config import config

    print(config.rpc_endpoint)
    print(config.rpc_user)
"""

import os
from pathlib import Path
from dataclasses import dataclass

from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Load .env from the project root (two levels up from this file)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"

load_dotenv(dotenv_path=_ENV_FILE)


# ---------------------------------------------------------------------------
# Config dataclass — typed, explicit, IDE-friendly
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    """Immutable configuration object built from environment variables."""

    rpc_user: str
    rpc_pass: str
    rpc_endpoint: str
    btc_network: str

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config instance from environment variables.

        Raises:
            EnvironmentError: If any required variable is missing.
        """
        missing = []

        rpc_user     = os.getenv("BTC_RPC_USER")
        rpc_pass     = os.getenv("BTC_RPC_PASS")
        rpc_endpoint = os.getenv("BTC_RPC_ENDPOINT")
        btc_network  = os.getenv("BTC_NETWORK", "regtest")

        if not rpc_user:
            missing.append("BTC_RPC_USER")
        if not rpc_pass:
            missing.append("BTC_RPC_PASS")
        if not rpc_endpoint:
            missing.append("BTC_RPC_ENDPOINT")

        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"Make sure your .env file exists at: {_ENV_FILE}\n"
                f"You can copy .env.example to .env to get started."
            )

        return cls(
            rpc_user=rpc_user,
            rpc_pass=rpc_pass,
            rpc_endpoint=rpc_endpoint,
            btc_network=btc_network,
        )


# ---------------------------------------------------------------------------
# Module-level singleton — import this everywhere
# ---------------------------------------------------------------------------
config = Config.from_env()



