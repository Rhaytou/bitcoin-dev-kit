import os
import hmac
import hashlib
import struct
import base64

from mnemonic import Mnemonic
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from coincurve import PrivateKey
from bitcoin.wallet import P2PKHBitcoinAddress
from bitcoin import SelectParams


# -----------------------
# Wallet manager
# -----------------------
# BIP-39 — Generates a mnemonic phrase and derives a seed from it (chain agnostic)
def _generate_mnemonic() -> bytes: # get (), return text to bytes
    """Generate a random 256-bit BIP-39 mnemonic and return it as UTF-8 bytes."""
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(256)
    mnemonic_text_to_bytes = mnemonic.encode("utf-8")
    return mnemonic_text_to_bytes
'''
mnemonic_text_to_bytes_1 = _generate_mnemonic()
'''

def _encrypt_mnemonic(mnemonic_bytes: bytes, key: bytes, iv: bytes) -> bytes: # get bytes, return bytes
    """Encrypt mnemonic bytes using AES-CBC."""
    aes_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_mnemonic_bytes = aes_cipher.encrypt(pad(mnemonic_bytes, AES.block_size))
    return encrypted_mnemonic_bytes
'''
key = b"1234567890123456" # AES key (Use secure key derivation (PBKDF2, scrypt, Argon2) instead of hardcoded key)
iv = b"1234567890123456" # IV (16 bytes) (Use random IV per encryption)
encrypted_mnemonic_bytes_1 = _encrypt_mnemonic(mnemonic_text_to_bytes_1, key, iv)
'''

def _encode_mnemonic(encrypted_mnemonic_bytes: bytes) -> str: # get bytes, return bytes to text
    """Base64-encode encrypted mnemonic bytes to a storable string."""
    encoded_encrypted_mnemonic_bytes_to_text = base64.b64encode(encrypted_mnemonic_bytes).decode("utf-8")
    return encoded_encrypted_mnemonic_bytes_to_text
'''
encoded_encrypted_mnemonic_bytes_to_text_1 = _encode_mnemonic(encrypted_mnemonic_bytes_1)
'''

def _create_mnemonic_file(encoded_encrypted_mnemonic_bytes_to_text: str, wallet_name: str) -> str: # get text, return file path as str
    """Save the encoded encrypted mnemonic to a .wallet file under ./wallets/."""
    directory = "./wallets"
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, f"{wallet_name}.wallet")
    with open(file_path, "w") as f:
        f.write(encoded_encrypted_mnemonic_bytes_to_text)
    return file_path
'''
wallet_name_1 = 'btc_main'
file_for_encoded_encrypted_mnemonic_1 = _create_mnemonic_file(encoded_encrypted_mnemonic_bytes_to_text_1, wallet_name_1)
'''

def _load_mnemonic(wallet_name: str) -> bytes: # get wallet_name for path, return text to bytes
    """Read the encoded encrypted mnemonic from a .wallet file and return as bytes."""
    file_path = os.path.join("./wallets", f"{wallet_name}.wallet")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Wallet file '{file_path}' does not exist.")
    with open(file_path, "r") as f:
        encoded_encrypted_mnemonic = f.read()
    encoded_encrypted_mnemonic_text_to_bytes = encoded_encrypted_mnemonic.encode("utf-8")
    return encoded_encrypted_mnemonic_text_to_bytes
'''
wallet_name_1 = 'btc_main'
encoded_encrypted_mnemonic_text_to_bytes_1 = _load_mnemonic(wallet_name_1)
'''

def _decode_mnemonic(encoded_encrypted_mnemonic_text_to_bytes: str) -> bytes: # get bytes, return bytes
    """Base64-decode the encoded mnemonic back to raw encrypted bytes."""
    encrypted_mnemonic_text_to_bytes = base64.b64decode(encoded_encrypted_mnemonic_text_to_bytes)
    return encrypted_mnemonic_text_to_bytes
'''
encrypted_mnemonic_text_to_bytes_1 = _decode_mnemonic(encoded_encrypted_mnemonic_text_to_bytes_1)
'''

def _decrypt_mnemonic(encrypted_wallet_bytes: bytes, key: bytes, iv: bytes) -> str: # get bytes, return bytes to text
    """Decrypt AES-CBC encrypted mnemonic bytes and return the mnemonic string."""
    aes_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_wallet_bytes), AES.block_size)
    mnemonic_bytes_to_text = decrypted_data.decode("utf-8")
    return mnemonic_bytes_to_text
'''
key = b"1234567890123456" # AES key
iv = b"1234567890123456" # IV (16 bytes)
mnemonic_bytes_to_text_1 = _decrypt_mnemonic(encrypted_mnemonic_text_to_bytes_1, key, iv) # Btc Seed
'''

def _get_seed(mnemonic_bytes_to_text: str) -> bytes:  # get text, return bytes
    """Derive a 512-bit BIP-39 seed from a mnemonic string."""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_bytes_to_text)
    return seed
'''
seed_1 = _get_seed(mnemonic_bytes_to_text_1) # Btc Seed
'''

class Bip_39:
    """High-level interface for BIP-39 wallet creation, loading, and deletion."""

    def create_wallet(self, wallet_name: str, key: bytes, iv: bytes) -> str:
        """Generate, encrypt, and save a new mnemonic wallet. Returns the file path."""
        mnemonic_bytes = _generate_mnemonic()
        encrypted_mnemonic = _encrypt_mnemonic(mnemonic_bytes, key, iv)
        encoded_mnemonic = _encode_mnemonic(encrypted_mnemonic)
        wallet_file_path = _create_mnemonic_file(encoded_mnemonic, wallet_name)
        return wallet_file_path

    def load_wallet(self, wallet_name: str, key: bytes, iv: bytes) -> str:
        """Load and decrypt an existing wallet. Returns the mnemonic string."""
        encoded_mnemonic_bytes = _load_mnemonic(wallet_name)
        encrypted_mnemonic_bytes = _decode_mnemonic(encoded_mnemonic_bytes)
        mnemonic_text = _decrypt_mnemonic(encrypted_mnemonic_bytes, key, iv)
        return mnemonic_text

    def get_seed(self, mnemonic_text: str) -> bytes:
        """Derive a BIP-39 seed from a mnemonic string."""
        return _get_seed(mnemonic_text)

    def delete_wallet(self, wallet_name: str) -> str:
        """Delete a wallet file. Returns the deleted file path."""
        file_path = os.path.join("./wallets", f"{wallet_name}.wallet")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Wallet '{wallet_name}' does not exist.")
        os.remove(file_path)
        return file_path
'''
bip39 = Bip_39()

key = b"1234567890123456"
iv = b"1234567890123456"

bip39.create_wallet("btc_main", key, iv)
bip39.create_wallet("eth_main", key, iv)

bip39.delete_wallet("btc_main")
bip39.delete_wallet("eth_main")

btc_mnemonic = bip39.load_wallet("btc_main", key, iv)
btc_seed = bip39.get_seed(btc_mnemonic)
'''


# BIP-32 — Derives an HD key tree from the seed (master key → child keys) (chain agnostic)
def _get_master_key(seed: bytes) -> tuple[bytes, bytes]:
    """Derive the BIP-32 master private key and chain code from a seed using HMAC-SHA512."""
    I = hmac.new(
        key=b"Bitcoin seed",
        msg=seed,
        digestmod=hashlib.sha512
    ).digest()
    master_private_key = I[:32]
    master_chain_code = I[32:]
    return master_private_key, master_chain_code
'''
btc_master_priv_1, btc_master_chain_code_1 = _get_master_key(seed_1) # Btc Master Key & Master Chain
'''

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # secp256k1 curve order — used to keep child keys within valid range

def _get_child_key_normal(parent_private_key, parent_chain_code, index):
    """Derive a normal (non-hardened) child key. Index range: 0 to 2^31-1."""
    data = parent_private_key + struct.pack(">L", index)
    I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()

    IL, IR = I[:32], I[32:]

    child_int = (
        int.from_bytes(IL, "big")
        + int.from_bytes(parent_private_key, "big")
    ) % SECP256K1_N

    return child_int.to_bytes(32, "big"), IR

def _get_child_key_hardened(parent_private_key, parent_chain_code, index):
    """Derive a hardened child key. Index range: 2^31 to 2^32-1. More secure, not derivable from public key."""
    data = b"\x00" + parent_private_key + struct.pack(">L", index)
    I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()

    IL, IR = I[:32], I[32:]

    child_int = (
        int.from_bytes(IL, "big")
        + int.from_bytes(parent_private_key, "big")
    ) % SECP256K1_N

    return child_int.to_bytes(32, "big"), IR

class Bip_32:
    """High-level interface for BIP-32 master and child key derivation."""

    def get_master_key(self, seed: bytes) -> tuple[bytes, bytes]:
        """Derive master private key and chain code from seed."""
        return _get_master_key(seed)

    def get_child_key(self, parent_private_key: bytes, parent_chain_code: bytes, index: int, hardened: bool = False) -> tuple[bytes, bytes]:
        """Derive a child key. Set hardened=True for hardened derivation."""
        if hardened:
            return _get_child_key_hardened(parent_private_key, parent_chain_code, index)
        else:
            return _get_child_key_normal(parent_private_key, parent_chain_code, index)
'''
bip32 = Bip_32()

btc_master_priv, btc_master_chain_code = bip32.get_master_key(btc_seed)
'''


# BIP-44 — Standardized multi-coin derivation paths: m / 44' / coin' / account' / change / index
HARDENED_OFFSET = 0x80000000  # Added to index to mark hardened derivation steps

def _derive_btc_bip44_addresses(btc_master_priv: bytes, btc_master_chain_code: bytes, count: int) -> list[list[bytes]]:
    """Derive `count` Bitcoin addresses following BIP-44 path: m/44'/0'/0'/0/i."""
    # BITCOIN BIP-44 Path: m / 44' / 0' / 0' / 0 / i
    ## m / 44'
    priv_44, chain_44 = _get_child_key_hardened(btc_master_priv, btc_master_chain_code, 44 + HARDENED_OFFSET)

    ## m / 44' / 0'
    priv_44_0, chain_44_0 = _get_child_key_hardened(priv_44, chain_44, 0 + HARDENED_OFFSET)

    ## m / 44' / 0' / 0'
    priv_44_0_0, chain_44_0_0 = _get_child_key_hardened(priv_44_0, chain_44_0, 0 + HARDENED_OFFSET)

    ## m / 44' / 0' / 0' / 0
    priv_ext, chain_ext = _get_child_key_normal(priv_44_0_0, chain_44_0_0, 0)

    ## m / 44' / 0' / 0' / 0 / i
    addresses = []
    for i in range(count):
        priv, chain = _get_child_key_normal(priv_ext, chain_ext, i)
        addresses.append([priv, chain])

    return addresses
'''
btc_addresses = _derive_btc_bip44_addresses(btc_master_priv, btc_master_chain_code, count=2) # btc_addresses[i] -> [private_key, chain_code]
'''

class Bip_44:
    """High-level interface for BIP-44 address derivation per chain."""

    def derive_bitcoin_addresses(self, btc_master_priv: bytes, btc_master_chain_code: bytes, count: int) -> list[list[bytes]]:
        """Derive `count` Bitcoin child keys via BIP-44 path."""
        return _derive_btc_bip44_addresses(btc_master_priv, btc_master_chain_code, count)

    def derive_ethereum_addresses(self, eth_master_priv: bytes, eth_master_chain_code: bytes, count: int) -> list[list[bytes]]:
        """Derive `count` Ethereum child keys via BIP-44 path."""
        return _derive_eth_bip44_addresses( eth_master_priv, eth_master_chain_code, count)
'''
bip44 = Bip_44()

btc_addresses = bip44.derive_bitcoin_addresses(btc_master_priv, btc_master_chain_code, count=2) # btc_addresses[i] -> [private_key, chain_code]
'''


# -----------------------
# Workflow
# -----------------------
# Wallet
## Class Bip_39
bip39 = Bip_39()

key = b"1234567890123456"
iv = b"1234567890123456"

'''
bip39.create_wallet("btc_main", key, iv)
bip39.delete_wallet("btc_main")
'''

btc_mnemonic = bip39.load_wallet("btc_main", key, iv)
btc_seed = bip39.get_seed(btc_mnemonic)

## Class Bip_32
bip32 = Bip_32()
btc_master_priv, btc_master_chain_code = bip32.get_master_key(btc_seed)

## Class Bip_44
bip44 = Bip_44()
btc_addresses = bip44.derive_bitcoin_addresses( btc_master_priv, btc_master_chain_code, count=5) # btc_addresses[i] -> [private_key, chain_code]
btc_priv_addr_0, btc_chain_addr_0 = btc_addresses[0]
btc_priv_addr_1, btc_chain_addr_1 = btc_addresses[1]
btc_priv_addr_2, btc_chain_addr_2 = btc_addresses[2]
btc_priv_addr_3, btc_chain_addr_3 = btc_addresses[3]
btc_priv_addr_4, btc_chain_addr_4 = btc_addresses[4]


# Private Key → Public Key → P2PKH Address
SelectParams("regtest")

def get_private_key(priv_key_bytes: bytes) -> PrivateKey:
    """Wrap raw private key bytes into a coincurve PrivateKey object."""
    return PrivateKey(priv_key_bytes)

def get_public_key(priv_key: PrivateKey, compressed=True) -> bytes:
    """Derive the public key from a private key. Compressed by default."""
    return priv_key.public_key.format(compressed=compressed)

def make_p2pkh_address(pubkey_bytes: bytes) -> str:
    """Generate a P2PKH Bitcoin address from a compressed public key."""
    return str(P2PKHBitcoinAddress.from_pubkey(pubkey_bytes))

## Sender
sender_priv = get_private_key(btc_priv_addr_0)
print(sender_priv)
sender_pub = get_public_key(sender_priv, compressed=True)
print(sender_pub)
sender_address = make_p2pkh_address(sender_pub)
print(sender_address)

## Receiver
receiver_priv = get_private_key(btc_priv_addr_1)
print(receiver_priv)
receiver_pub = get_public_key(receiver_priv, compressed=True)
print(receiver_pub)
receiver_address = make_p2pkh_address(receiver_pub)
print(receiver_address)






