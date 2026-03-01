"""
core/crypto.py
==============
Shared cryptographic primitives for the Bitcoin Dev Kit.

This module centralises all low-level key and address functions that were
previously duplicated across bitcoin-wallet/wallet.py and
bitcoin-transactions/tx_templates.py. Every module imports from here —
nothing is redefined elsewhere.

Contents:
    Key helpers     — get_private_key, get_public_key
    Address helpers — make_p2pkh_address, make_scriptpubkey_from_address
    Hash helpers    — double_sha256
    TX serialisation helpers — encode_varint, encode_uint32, encode_uint64,
                               little_endian_txid
"""

import hashlib

from coincurve import PrivateKey
from bitcoin.wallet import CBitcoinAddress, P2PKHBitcoinAddress


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def get_private_key(priv_key_bytes: bytes) -> PrivateKey:
    """Wrap raw private key bytes into a coincurve PrivateKey object.

    Args:
        priv_key_bytes: 32-byte raw private key.

    Returns:
        A coincurve PrivateKey instance.
    """
    return PrivateKey(priv_key_bytes)


def get_public_key(priv_key: PrivateKey, compressed: bool = True) -> bytes:
    """Derive the public key from a private key.

    Args:
        priv_key:   A coincurve PrivateKey instance.
        compressed: Return compressed public key (33 bytes) if True,
                    uncompressed (65 bytes) if False. Default: True.

    Returns:
        Public key as bytes.
    """
    return priv_key.public_key.format(compressed=compressed)


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def make_p2pkh_address(pubkey_bytes: bytes) -> str:
    """Generate a P2PKH Bitcoin address from a compressed public key.

    Args:
        pubkey_bytes: Compressed public key (33 bytes).

    Returns:
        Base58Check-encoded P2PKH address string.
    """
    return str(P2PKHBitcoinAddress.from_pubkey(pubkey_bytes))


def make_scriptpubkey_from_address(address: str) -> bytes:
    """Convert a Bitcoin address to its scriptPubKey bytes.

    Args:
        address: Base58Check-encoded Bitcoin address.

    Returns:
        scriptPubKey as raw bytes.
    """
    addr = CBitcoinAddress(address)
    return bytes(addr.to_scriptPubKey())


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def double_sha256(data: bytes) -> bytes:
    """Apply SHA-256 twice — standard Bitcoin hashing (Hash256).

    Args:
        data: Raw bytes to hash.

    Returns:
        32-byte digest.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Transaction serialisation helpers
# ---------------------------------------------------------------------------

def encode_varint(i: int) -> bytes:
    """Encode an integer as a Bitcoin variable-length integer (varint).

    Args:
        i: Non-negative integer to encode.

    Returns:
        1, 3, 5, or 9 bytes depending on magnitude.
    """
    if i < 0xfd:
        return i.to_bytes(1, "little")
    elif i <= 0xffff:
        return b"\xfd" + i.to_bytes(2, "little")
    elif i <= 0xffffffff:
        return b"\xfe" + i.to_bytes(4, "little")
    else:
        return b"\xff" + i.to_bytes(8, "little")


def encode_uint32(i: int) -> bytes:
    """Encode an integer as 4-byte little-endian (uint32).

    Args:
        i: Non-negative integer.

    Returns:
        4 bytes, little-endian.
    """
    return i.to_bytes(4, "little")


def encode_uint64(i: int) -> bytes:
    """Encode an integer as 8-byte little-endian (uint64).

    Args:
        i: Non-negative integer.

    Returns:
        8 bytes, little-endian.
    """
    return i.to_bytes(8, "little")


def little_endian_txid(txid_hex: str) -> bytes:
    """Reverse a hex txid string to little-endian bytes.

    Bitcoin stores txids in internal byte order (little-endian) in raw
    transactions, which is the reverse of the display order.

    Args:
        txid_hex: 64-character hex string (big-endian / display order).

    Returns:
        32 bytes in little-endian (internal) order.
    """
    return bytes.fromhex(txid_hex)[::-1]


