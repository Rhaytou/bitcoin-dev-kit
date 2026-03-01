"""
core/rpc.py
===========
Bitcoin JSON-RPC client for the Bitcoin Dev Kit.

The BitcoinRPC class and the get_rpc_client() factory live here.
Both bitcoin-client/client.py and bitcoin-transactions/tx_templates.py
import from this module — the class is never redefined elsewhere.

Usage:
    from core.rpc import get_rpc_client

    rpc = get_rpc_client()
    info = rpc.getblockchaininfo()
    result = rpc.call("getblockcount", [])
"""

import requests
from requests.auth import HTTPBasicAuth

from core.config import config


# ---------------------------------------------------------------------------
# RPC Client
# ---------------------------------------------------------------------------

class BitcoinRPC:
    """JSON-RPC client for communicating with a Bitcoin node."""

    def __init__(self, endpoint: str, session: requests.Session, timeout: int = 30):
        """Set up the RPC connection.

        Args:
            endpoint: Full URL of the Bitcoin node RPC endpoint.
            session:  A requests.Session pre-configured with auth.
            timeout:  Request timeout in seconds. Default: 30.
        """
        self._url = endpoint
        self._session = session
        self._timeout = timeout
        self._session.headers.update({
            "Content-Type": "application/json"
        })

    def call(self, method: str, params: list = None, request_id: str = "bitcoin-dev-kit"):
        """Send a JSON-RPC request and return the result.

        Args:
            method:     Bitcoin RPC method name (e.g. "getblockchaininfo").
            params:     List of positional parameters. Default: [].
            request_id: Arbitrary string echoed back by the node.

        Returns:
            The `result` field of the JSON-RPC response.

        Raises:
            requests.HTTPError: On non-2xx HTTP responses.
            RuntimeError:       On RPC-level errors returned by the node.
        """
        if params is None:
            params = []

        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }

        response = self._session.post(
            self._url,
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()

        data = response.json()
        if data.get("error") is not None:
            raise RuntimeError(data["error"])

        return data["result"]

    # ------------------------------------------------------------------
    # Convenience shortcuts
    # ------------------------------------------------------------------

    def getblockchaininfo(self) -> dict:
        """Shortcut for the getblockchaininfo RPC call."""
        return self.call("getblockchaininfo")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_rpc_client() -> BitcoinRPC:
    """Create and return a BitcoinRPC client configured from the environment.

    Credentials and endpoint are read from core.config (which loads .env).
    This is the single place in the project where an RPC session is built —
    never instantiate BitcoinRPC directly with hardcoded values.

    Returns:
        A ready-to-use BitcoinRPC instance.
    """
    session = requests.Session()
    session.auth = HTTPBasicAuth(config.rpc_user, config.rpc_pass)
    return BitcoinRPC(endpoint=config.rpc_endpoint, session=session)








