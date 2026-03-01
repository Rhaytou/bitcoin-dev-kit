"""
tests/test_tx_templates.py
==========================
Unit tests for bitcoin-transactions/tx_templates.py — serialization only.
No node required. Tests raw byte output of primitives and transaction model.
"""

import sys
import pytest
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

sys.modules["wallet"] = MagicMock()

_spec = importlib.util.spec_from_file_location(
    "tx_templates",
    Path(__file__).resolve().parent.parent / "bitcoin-transactions" / "tx_templates.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

TxInput              = _mod.TxInput
TxOutput             = _mod.TxOutput
LegacyRawTransaction = _mod.LegacyRawTransaction
SIGHASH_ALL          = _mod.SIGHASH_ALL
SIGHASH_NONE         = _mod.SIGHASH_NONE
SIGHASH_SINGLE       = _mod.SIGHASH_SINGLE
SIGHASH_ANYONECANPAY = _mod.SIGHASH_ANYONECANPAY
SIGHASH_DEFAULT      = _mod.SIGHASH_DEFAULT


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_sighash_values():
    assert SIGHASH_ALL          == 0x01
    assert SIGHASH_NONE         == 0x02
    assert SIGHASH_SINGLE       == 0x03
    assert SIGHASH_ANYONECANPAY == 0x80
    assert SIGHASH_DEFAULT      == 0x00


# ---------------------------------------------------------------------------
# TxInput serialization
# ---------------------------------------------------------------------------

DUMMY_TXID = "a" * 64  # 32-byte txid in hex

def test_txinput_serialize_length():
    tx_input = TxInput(DUMMY_TXID, vout=0)
    serialized = tx_input.serialize()
    # 32 (txid) + 4 (vout) + 1 (scriptSig varint=0) + 0 (empty scriptSig) + 4 (sequence)
    assert len(serialized) == 41

def test_txinput_vout_encoding():
    tx_input = TxInput(DUMMY_TXID, vout=1)
    serialized = tx_input.serialize()
    # vout starts at byte 32, little-endian
    assert serialized[32:36] == b"\x01\x00\x00\x00"

def test_txinput_default_sequence():
    tx_input = TxInput(DUMMY_TXID, vout=0)
    serialized = tx_input.serialize()
    # sequence is last 4 bytes — default 0xffffffff
    assert serialized[-4:] == b"\xff\xff\xff\xff"

def test_txinput_custom_sequence():
    tx_input = TxInput(DUMMY_TXID, vout=0, sequence=0)
    serialized = tx_input.serialize()
    assert serialized[-4:] == b"\x00\x00\x00\x00"

def test_txinput_txid_is_little_endian():
    txid = "00" * 30 + "0102"
    tx_input = TxInput(txid, vout=0)
    # first byte should be 0x02 (reversed)
    assert tx_input.txid[0] == 0x02


# ---------------------------------------------------------------------------
# TxOutput serialization
# ---------------------------------------------------------------------------

DUMMY_SCRIPT = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"  # P2PKH scriptPubKey

def test_txoutput_serialize_length():
    tx_output = TxOutput(value_sats=100_000_000, scriptPubKey=DUMMY_SCRIPT)
    serialized = tx_output.serialize()
    # 8 (value) + 1 (script varint) + len(script)
    assert len(serialized) == 8 + 1 + len(DUMMY_SCRIPT)

def test_txoutput_value_encoding():
    tx_output = TxOutput(value_sats=100_000_000, scriptPubKey=b"\x00")
    serialized = tx_output.serialize()
    # 1 BTC = 100_000_000 sats, little-endian 8 bytes
    assert serialized[:8] == b"\x00\xe1\xf5\x05\x00\x00\x00\x00"

def test_txoutput_zero_value():
    tx_output = TxOutput(value_sats=0, scriptPubKey=b"\x00")
    serialized = tx_output.serialize()
    assert serialized[:8] == b"\x00\x00\x00\x00\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# LegacyRawTransaction serialization
# ---------------------------------------------------------------------------

def test_legacy_tx_empty_serialize_length():
    tx = LegacyRawTransaction(version=1, locktime=0)
    serialized = tx.serialize()
    # 4 (version) + 1 (input count varint=0) + 1 (output count varint=0) + 4 (locktime)
    assert len(serialized) == 10

def test_legacy_tx_version_encoding():
    tx = LegacyRawTransaction(version=1, locktime=0)
    serialized = tx.serialize()
    assert serialized[:4] == b"\x01\x00\x00\x00"

def test_legacy_tx_locktime_encoding():
    tx = LegacyRawTransaction(version=1, locktime=0)
    serialized = tx.serialize()
    assert serialized[-4:] == b"\x00\x00\x00\x00"

def test_legacy_tx_with_input_and_output():
    tx = LegacyRawTransaction(version=1, locktime=0)
    tx.add_input(TxInput(DUMMY_TXID, vout=0))
    tx.add_output(TxOutput(value_sats=50_000_000, scriptPubKey=DUMMY_SCRIPT))
    serialized = tx.serialize()
    assert len(serialized) > 10

def test_legacy_tx_hex_is_string():
    tx = LegacyRawTransaction(version=1, locktime=0)
    assert isinstance(tx.hex(), str)

def test_legacy_tx_hex_matches_serialize():
    tx = LegacyRawTransaction(version=1, locktime=0)
    assert tx.hex() == tx.serialize().hex()

def test_legacy_tx_input_count_in_serialized():
    tx = LegacyRawTransaction(version=1, locktime=0)
    tx.add_input(TxInput(DUMMY_TXID, vout=0))
    tx.add_input(TxInput(DUMMY_TXID, vout=1))
    serialized = tx.serialize()
    # byte 4 is input count varint — should be 2
    assert serialized[4] == 2




