"""
core/
=====
Shared utilities for the Bitcoin Dev Kit.

All Python modules in this project import from core/ — nothing is
redefined or duplicated in the individual module directories.

Modules:
    config  — Environment-based configuration (reads .env via python-dotenv)
    rpc     — BitcoinRPC class and get_rpc_client() factory
    crypto  — Shared key, address, hashing, and serialisation helpers
"""


