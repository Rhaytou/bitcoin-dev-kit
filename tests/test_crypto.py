"""
tests/test_crypto.py
====================
Unit tests for core/crypto.py — pure function tests, no node required.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.crypto import (
    double_sha256,
    encode_varint,
    encode_uint32,
    encode_uint64,
    little_endian_txid,
)


# ---------------------------------------------------------------------------
# double_sha256
# ---------------------------------------------------------------------------

def test_double_sha256_known_vector():
    # SHA256(SHA256(b"")) — known value
    result = double_sha256(b"")
    assert result.hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"

def test_double_sha256_returns_32_bytes():
    assert len(double_sha256(b"bitcoin")) == 32

def test_double_sha256_deterministic():
    assert double_sha256(b"test") == double_sha256(b"test")


# ---------------------------------------------------------------------------
# encode_varint
# ---------------------------------------------------------------------------

def test_encode_varint_single_byte():
    assert encode_varint(0) == b"\x00"
    assert encode_varint(0xfc) == b"\xfc"

def test_encode_varint_two_bytes():
    assert encode_varint(0xfd) == b"\xfd\xfd\x00"
    assert encode_varint(0xffff) == b"\xfd\xff\xff"

def test_encode_varint_four_bytes():
    assert encode_varint(0x10000) == b"\xfe\x00\x00\x01\x00"

def test_encode_varint_eight_bytes():
    assert encode_varint(0x100000000) == b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"


# ---------------------------------------------------------------------------
# encode_uint32
# ---------------------------------------------------------------------------

def test_encode_uint32_zero():
    assert encode_uint32(0) == b"\x00\x00\x00\x00"

def test_encode_uint32_one():
    assert encode_uint32(1) == b"\x01\x00\x00\x00"

def test_encode_uint32_max():
    assert encode_uint32(0xffffffff) == b"\xff\xff\xff\xff"

def test_encode_uint32_length():
    assert len(encode_uint32(12345)) == 4


# ---------------------------------------------------------------------------
# encode_uint64
# ---------------------------------------------------------------------------

def test_encode_uint64_zero():
    assert encode_uint64(0) == b"\x00\x00\x00\x00\x00\x00\x00\x00"

def test_encode_uint64_one():
    assert encode_uint64(1) == b"\x01\x00\x00\x00\x00\x00\x00\x00"

def test_encode_uint64_length():
    assert len(encode_uint64(100_000_000)) == 8

def test_encode_uint64_satoshis():
    # 1 BTC = 100_000_000 satoshis
    assert encode_uint64(100_000_000) == b"\x00\xe1\xf5\x05\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# little_endian_txid
# ---------------------------------------------------------------------------

def test_little_endian_txid_reverses_bytes():
    txid = "aabbccdd" + "00" * 28
    result = little_endian_txid(txid)
    assert result == bytes.fromhex(txid)[::-1]

def test_little_endian_txid_length():
    txid = "a" * 64
    assert len(little_endian_txid(txid)) == 32

def test_little_endian_txid_known():
    txid = "0000000000000000000000000000000000000000000000000000000000000001"
    result = little_endian_txid(txid)
    assert result[0] == 0x01
    assert result[-1] == 0x00