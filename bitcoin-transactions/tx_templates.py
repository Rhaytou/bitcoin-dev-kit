"""
bitcoin-transactions/tx_templates.py
=====================================
Raw Bitcoin transaction construction and signing — from scratch.
No library wrappers. No shortcuts. Just the protocol.

Covers the full transaction lifecycle:
    1. Load wallet keys via bitcoin-wallet (BIP-39/32/44)
    2. Derive addresses and scriptPubKeys from raw keys
    3. Connect to the node via core.rpc
    4. Build a raw transaction byte by byte
    5. Sign using the correct sighash algorithm for the input type
    6. Broadcast and confirm via RPC

Transaction types covered (or stubbed for future implementation):
    Legacy (no witness)
        P2PK
        P2PKH ← implemented
        Bare Multisig
        P2SH
        OP_RETURN
        Coinbase

    SegWit v0 (BIP141 + BIP143)
        P2WPKH
        P2WSH
        P2SH-P2WPKH (nested)
        P2SH-P2WSH  (nested)

    SegWit v1 (BIP341)
        P2TR (Taproot): key-path / script-path

    Non-standard script

Transaction wire format:
    ├── version          (4 bytes, little-endian)
    ├── [marker]         (1 byte, 0x00 — SegWit only)
    ├── [flag]           (1 byte, 0x01 — SegWit only)
    ├── input_count      (varint)
    ├── vin[]
    │     ├── prev_txid        (32 bytes, little-endian)
    │     ├── prev_vout        (4 bytes, little-endian)
    │     ├── scriptSig_length (varint)
    │     ├── scriptSig        (empty for SegWit inputs)
    │     ├── sequence         (4 bytes, little-endian)
    │     └── [witness]        (stack items — SegWit only)
    ├── output_count     (varint)
    ├── vout[]
    │     ├── value            (8 bytes, little-endian, satoshis)
    │     ├── scriptPubKey_length (varint)
    │     └── scriptPubKey
    └── locktime         (4 bytes, little-endian)

Run directly:
    python3 bitcoin-transactions/tx_templates.py
"""


import os
import sys
import json
from pathlib import Path

from coincurve import PrivateKey
from bitcoin import SelectParams

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.crypto import (
    get_private_key,
    get_public_key,
    make_p2pkh_address,
    make_scriptpubkey_from_address,
    double_sha256,
    encode_varint,
    encode_uint32,
    encode_uint64,
    little_endian_txid,
)
from core.rpc import get_rpc_client

current_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(os.path.join(project_root, "bitcoin-wallet"))
import wallet


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Legacy & SegWit v0 (BIP143) sighash types
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80  # combined via bitwise OR with the above

# Taproot (BIP341) sighash types
SIGHASH_DEFAULT = 0x00  # equivalent to SIGHASH_ALL for Taproot


# ---------------------------------------------------------------------------
# Transaction primitives
# ---------------------------------------------------------------------------
class TxInput:
    """Represents a single transaction input."""

    def __init__(self, txid_hex: str, vout: int, sequence: int = 0xffffffff):
        self.txid     = little_endian_txid(txid_hex)
        self.vout     = vout
        self.scriptSig = b""
        self.sequence = sequence

    def serialize(self) -> bytes:
        """Serialize the input to raw bytes."""
        return (
            self.txid
            + encode_uint32(self.vout)
            + encode_varint(len(self.scriptSig))
            + self.scriptSig
            + encode_uint32(self.sequence)
        )

class TxOutput:
    """Represents a single transaction output."""

    def __init__(self, value_sats: int, scriptPubKey: bytes):
        self.value       = value_sats
        self.scriptPubKey = scriptPubKey

    def serialize(self) -> bytes:
        """Serialize the output to raw bytes."""
        return (
            encode_uint64(self.value)
            + encode_varint(len(self.scriptPubKey))
            + self.scriptPubKey
        )


# ---------------------------------------------------------------------------
# Legacy Transactions
# ---------------------------------------------------------------------------
class LegacyRawTransaction:
    """Builds and signs a raw Bitcoin legacy transaction from scratch."""

    def __init__(self, version: int = 1, locktime: int = 0):
        self.version  = version
        self.inputs   = []
        self.outputs  = []
        self.locktime = locktime

    def add_input(self, tx_input: TxInput):
        """Add an input to the transaction."""
        self.inputs.append(tx_input)

    def add_output(self, tx_output: TxOutput):
        """Add an output to the transaction."""
        self.outputs.append(tx_output)

    def serialize(self) -> bytes:
        """Serialize the full transaction to raw bytes."""
        result  = encode_uint32(self.version)
        result += encode_varint(len(self.inputs))
        for txin in self.inputs:
            result += txin.serialize()
        result += encode_varint(len(self.outputs))
        for txout in self.outputs:
            result += txout.serialize()
        result += encode_uint32(self.locktime)
        return result

    def hex(self) -> str:
        """Return the serialized transaction as a hex string."""
        return self.serialize().hex()

    def sign_input_legacy(
        self,
        input_index: int,
        privkey: PrivateKey,
        prev_scriptPubKey: bytes,
    ):
        """Sign a legacy (P2PKH) input using SIGHASH_ALL.

        Computes the sighash, signs it with the private key, and injects
        the resulting scriptSig into the input at input_index.

        Args:
            input_index:       Index of the input to sign.
            privkey:           coincurve PrivateKey of the UTXO owner.
            prev_scriptPubKey: scriptPubKey of the UTXO being spent.
        """
        # Build the preimage for signing
        preimage  = encode_uint32(self.version)
        preimage += encode_varint(len(self.inputs))

        for i, txin in enumerate(self.inputs):
            preimage += txin.txid
            preimage += encode_uint32(txin.vout)
            if i == input_index:
                preimage += encode_varint(len(prev_scriptPubKey))
                preimage += prev_scriptPubKey
            else:
                preimage += encode_varint(0)
            preimage += encode_uint32(txin.sequence)

        preimage += encode_varint(len(self.outputs))
        for txout in self.outputs:
            preimage += txout.serialize()

        preimage += encode_uint32(self.locktime)
        preimage += encode_uint32(SIGHASH_ALL)

        sighash   = double_sha256(preimage)
        signature = privkey.sign(sighash, hasher=None) + b"\x01"  # SIGHASH_ALL
        pubkey    = privkey.public_key.format(compressed=True)

        self.inputs[input_index].scriptSig = (
            encode_varint(len(signature)) + signature
            + encode_varint(len(pubkey))  + pubkey
        )

## P2PK

## P2PKH
def p2pkh_temp():
    """Build, sign, and broadcast a P2PKH transaction on regtest."""
    SelectParams("regtest")

    # NOTE: Replace with a securely derived key (PBKDF2/scrypt/Argon2) and
    # a random IV in any non-demo context.
    key = b"1234567890123456"
    iv  = b"1234567890123456"

    # --- Load wallet keys ---
    bip39 = wallet.Bip_39()
    btc_mnemonic = bip39.load_wallet("btc_main", key, iv)
    btc_seed     = bip39.get_seed(btc_mnemonic)

    bip32 = wallet.Bip_32()
    btc_master_priv, btc_master_chain_code = bip32.get_master_key(btc_seed)

    bip44 = wallet.Bip_44()
    btc_addresses = bip44.derive_bitcoin_addresses(
        btc_master_priv, btc_master_chain_code, count=2
    )

    btc_priv_addr_0, _ = btc_addresses[0]
    btc_priv_addr_1, _ = btc_addresses[1]

    # --- Derive keys and addresses ---
    sender_priv      = get_private_key(btc_priv_addr_0)
    sender_pub       = get_public_key(sender_priv)
    sender_address   = make_p2pkh_address(sender_pub)

    receiver_priv    = get_private_key(btc_priv_addr_1)
    receiver_pub     = get_public_key(receiver_priv)
    receiver_address = make_p2pkh_address(receiver_pub)

    # --- Connect to node ---
    rpc = get_rpc_client()

    # Mine 500 blocks to the sender so they have spendable UTXOs
    rpc.call("generatetoaddress", [500, sender_address])

    # --- Find a UTXO ---
    scan    = rpc.call("scantxoutset", ["start", [f"addr({sender_address})"]])
    utxo    = scan["unspents"][0]

    # --- Build transaction ---
    tx = LegacyRawTransaction(version=1, locktime=0)

    tx_input = TxInput(txid_hex=utxo["txid"], vout=utxo["vout"])
    tx.add_input(tx_input)

    input_amount_sats = int(float(utxo["amount"]) * 100_000_000)
    output_amount     = input_amount_sats - 1000  # subtract fee
    script_pubkey     = make_scriptpubkey_from_address(receiver_address)
    tx.add_output(TxOutput(value_sats=output_amount, scriptPubKey=script_pubkey))

    # --- Sign ---
    prev_scriptPubKey = make_scriptpubkey_from_address(sender_address)
    tx.sign_input_legacy(
        input_index=0,
        privkey=sender_priv,
        prev_scriptPubKey=prev_scriptPubKey,
    )

    # --- Broadcast ---
    raw_tx_hex = tx.hex()
    print(f"Signed Raw Tx: {raw_tx_hex}")

    txid = rpc.call("sendrawtransaction", [raw_tx_hex])
    print(f"TXID: {txid}")

    # --- Confirm ---
    tx_detail = rpc.call("getrawtransaction", [txid, True])
    print(json.dumps(tx_detail, indent=4))

    mempool = rpc.call("getrawmempool", [True])
    print(json.dumps(mempool, indent=4))

    # Mine to confirm
    rpc.call("generatetoaddress", [10, sender_address])

    mempool = rpc.call("getrawmempool", [True])
    print(json.dumps(mempool, indent=4))

## Bare Multisig

## P2SH

## OP_RETURN

## Coinbase


# ---------------------------------------------------------------------------
# SegWit v0
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Taproot (P2TR)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Non-standard script
# ---------------------------------------------------------------------------



if __name__ == "__main__":
    p2pkh_temp()









