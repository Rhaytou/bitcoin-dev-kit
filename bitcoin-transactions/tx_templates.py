import os
import sys
import json
import hashlib

from coincurve import PrivateKey
from bitcoin import SelectParams
from bitcoin.wallet import CBitcoinAddress, P2PKHBitcoinAddress


# Add the wallet and client paths and scripts
current_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(current_dir, ".."))

sys.path.append(os.path.join(project_root, "bitcoin-wallet"))
import wallet

sys.path.append(os.path.join(project_root, "bitcoin-client"))
import client


# Transactions
'''
Bitcoin Transactions Types
    Legacy (no witness)
        P2PK
        P2PKH
        Bare Multisig
        P2SH
        OP_RETURN
        Non-standard script

    SegWit v0
        P2WPKH
        P2WSH
        P2SH-P2WPKH (nested)
        P2SH-P2WSH (nested)

    SegWit v1
        P2TR (Taproot): key-path - script-path

Transaction structure types (serialization layer)
    Coinbase transaction (special input rules)
    Legacy transaction (pre-SegWit serialization)
    SegWit v0 transaction (marker + flag + witness)
    SegWit v1+ transaction (Taproot serialization rules)

Signature hash types (legacy + SegWit + Taproot)
   SIGHASH_ALL
   SIGHASH_NONE
   SIGHASH_SINGLE
   SIGHASH_ANYONECANPAY (modifier)
   SIGHASH_ALL|ANYONECANPAY
   SIGHASH_NONE|ANYONECANPAY
   SIGHASH_SINGLE|ANYONECANPAY
   Taproot SIGHASH_DEFAULT (implicit ALL)
   Taproot tagged hash algorithm (different digest algorithm than legacy)

Locktime / sequence semantics
   nLockTime (block height / timestamp)
   nSequence (RBF signaling)
   nSequence relative locktime (BIP68)
   CLTV (OP_CHECKLOCKTIMEVERIFY)
   CSV (OP_CHECKSEQUENCEVERIFY)

Transaction model
    ├── version
    ├── [marker]
    ├── [flag]
    ├── input_count
    ├── vin[]
    │     ├── prev_txid
    │     ├── prev_vout
    │     ├── scriptSig_length
    │     ├── scriptSig
    │     ├── sequence
    │     └── [witness]
    ├── output_count
    ├── vout[]
    │     ├── value
    │     ├── scriptPubKey_length
    │     └── scriptPubKey
    └── locktime
'''

## Coinbase

## OP_RETURN

## P2pk

## Multisig

## P2pkh
SelectParams("regtest")
SIGHASH_ALL = 1  # Signature covers all inputs and outputs

def encode_varint(i: int) -> bytes:
    """Encode an integer as a Bitcoin variable-length integer."""
    if i < 0xfd:
        return i.to_bytes(1, "little")
    elif i <= 0xffff:
        return b"\xfd" + i.to_bytes(2, "little")
    elif i <= 0xffffffff:
        return b"\xfe" + i.to_bytes(4, "little")
    else:
        return b"\xff" + i.to_bytes(8, "little")

def encode_uint32(i: int) -> bytes:
    """Encode an integer as 4-byte little-endian."""
    return i.to_bytes(4, "little")

def encode_uint64(i: int) -> bytes:
    """Encode an integer as 8-byte little-endian."""
    return i.to_bytes(8, "little")

def little_endian_txid(txid_hex: str) -> bytes:
    """Reverse a hex txid to little-endian bytes as used in raw transactions."""
    return bytes.fromhex(txid_hex)[::-1]

def double_sha256(b: bytes) -> bytes:
    """Apply SHA256 twice — standard Bitcoin hashing."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def get_private_key(priv_key_bytes: bytes) -> PrivateKey:
    """Wrap raw private key bytes into a coincurve PrivateKey object."""
    return PrivateKey(priv_key_bytes)

def get_public_key(priv_key: PrivateKey, compressed=True) -> bytes:
    """Derive the public key from a private key. Compressed by default."""
    return priv_key.public_key.format(compressed=compressed)

def make_p2pkh_address(pubkey_bytes: bytes) -> str:
    """Generate a P2PKH Bitcoin address from a public key."""
    return str(P2PKHBitcoinAddress.from_pubkey(pubkey_bytes))

def make_scriptpubkey_from_address(address: str) -> bytes:
    """Convert a Bitcoin address to its scriptPubKey bytes."""
    addr = CBitcoinAddress(address)
    return bytes(addr.to_scriptPubKey())

class TxInput:
    """Represents a single transaction input."""

    def __init__(self, txid_hex: str, vout: int, sequence=0xffffffff):
        self.txid = little_endian_txid(txid_hex)
        self.vout = vout
        self.scriptSig = b""
        self.sequence = sequence

    def serialize(self) -> bytes:
        """Serialize the input to raw bytes."""
        result = b""
        result += self.txid
        result += encode_uint32(self.vout)
        result += encode_varint(len(self.scriptSig))
        result += self.scriptSig
        result += encode_uint32(self.sequence)
        return result

class TxOutput:
    """Represents a single transaction output."""

    def __init__(self, value_sats: int, scriptPubKey: bytes):
        self.value = value_sats
        self.scriptPubKey = scriptPubKey

    def serialize(self) -> bytes:
        """Serialize the output to raw bytes."""
        result = b""
        result += encode_uint64(self.value)
        result += encode_varint(len(self.scriptPubKey))
        result += self.scriptPubKey
        return result

class RawTransaction:
    """Builds and signs a raw Bitcoin legacy transaction from scratch."""

    def __init__(self, version=1, locktime=0):
        self.version = version
        self.inputs = []
        self.outputs = []
        self.locktime = locktime

    def add_input(self, tx_input: TxInput):
        """Add an input to the transaction."""
        self.inputs.append(tx_input)

    def add_output(self, tx_output: TxOutput):
        """Add an output to the transaction."""
        self.outputs.append(tx_output)

    def serialize(self) -> bytes:
        """Serialize the full transaction to raw bytes."""
        result = b""
        result += encode_uint32(self.version)
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

    def sign_input_legacy(self, input_index: int, privkey: PrivateKey, prev_scriptPubKey: bytes):
        """Sign a legacy (P2PKH) input using SIGHASH_ALL and inject the scriptSig."""
        tmp_tx = b""
        tmp_tx += encode_uint32(self.version)
        tmp_tx += encode_varint(len(self.inputs))

        for i, txin in enumerate(self.inputs):
            tmp_tx += txin.txid
            tmp_tx += encode_uint32(txin.vout)

            if i == input_index:
                tmp_tx += encode_varint(len(prev_scriptPubKey))
                tmp_tx += prev_scriptPubKey
            else:
                tmp_tx += encode_varint(0)

            tmp_tx += encode_uint32(txin.sequence)

        tmp_tx += encode_varint(len(self.outputs))
        for txout in self.outputs:
            tmp_tx += txout.serialize()

        tmp_tx += encode_uint32(self.locktime)
        tmp_tx += encode_uint32(SIGHASH_ALL)

        sighash = double_sha256(tmp_tx)

        signature = privkey.sign(sighash, hasher=None)
        signature += b"\x01"  # Append SIGHASH_ALL byte

        pubkey = privkey.public_key.format(compressed=True)

        scriptSig = (
            encode_varint(len(signature)) +
            signature +
            encode_varint(len(pubkey)) +
            pubkey
        )

        self.inputs[input_index].scriptSig = scriptSig
''' '''
btc_priv = get_private_key(wallet.btc_priv_addr_0)
receiver_priv = get_private_key(wallet.btc_priv_addr_1)

sender_pub = get_public_key(btc_priv, compressed=True)
receiver_pub = get_public_key(receiver_priv, compressed=True)

sender_address = make_p2pkh_address(sender_pub)
receiver_address = make_p2pkh_address(receiver_pub)

generatetoaddress = client.RPC_BTC_NGINX.call("generatetoaddress", [500, sender_address])
generatetoaddress_final = json.dumps(generatetoaddress, indent=4)
#print(generatetoaddress_final)

tx = RawTransaction(version=1, locktime=0)

scantxoutset = client.RPC_BTC_NGINX.call("scantxoutset", ["start", [f"addr({sender_address})"]])
utxo = scantxoutset["unspents"][0]
tx_input = TxInput(txid_hex=utxo["txid"], vout=utxo["vout"])
tx.add_input(tx_input)

input_amount_sats = int(float(utxo["amount"]) * 100_000_000)
output_amount = input_amount_sats - 1000
script_pubkey = make_scriptpubkey_from_address(receiver_address)
tx_output = TxOutput(value_sats=output_amount, scriptPubKey=script_pubkey)
tx.add_output(tx_output)
prev_scriptPubKey = make_scriptpubkey_from_address(sender_address)
tx.sign_input_legacy(input_index=0, privkey=btc_priv, prev_scriptPubKey=prev_scriptPubKey)

final_raw_tx_hex = tx.hex()
print(f'Signed Raw Tx: {final_raw_tx_hex}')

txid = client.RPC_BTC_NGINX.call("sendrawtransaction", [final_raw_tx_hex])
print("TXID:", txid)

tx = client.RPC_BTC_NGINX.call("getrawtransaction", [txid, True])
print(json.dumps(tx, indent=4))

getrawmempool = client.RPC_BTC_NGINX.call("getrawmempool", [True])
print(json.dumps(getrawmempool, indent=4))

generatetoaddress = client.RPC_BTC_NGINX.call("generatetoaddress", [10, sender_address])
generatetoaddress_final = json.dumps(generatetoaddress, indent=4)
print(generatetoaddress_final)

getrawmempool = client.RPC_BTC_NGINX.call("getrawmempool", [True])
print(json.dumps(getrawmempool, indent=4))


## P2sh

## SegWit (P2WPKH, P2WSH, P2SH-P2WPKH, P2SH-P2WSH)

## Segwit Taproot (P2TR) (key-path or script-path)


















