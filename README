# Bitcoin Dev Kit

A multi-chain developer kit built from the ground up. This is a complete, layered reference implementation of blockchain technology — from cryptographic primitives to a working GUI. It is not an application and not a tutorial. It is working code at every layer: node infrastructure, key derivation, raw transaction construction, RPC client, and interface.

Each layer is intentionally minimal, documented, and runnable so a developer can read it, understand it, and extend it. The kit covers multiple blockchain networks — starting with Bitcoin, then Ethereum, then others — each implemented with the same depth and the same philosophy: no shortcuts, no library wrappers hiding the protocol, just the real thing at every level.

The overall project is composed of multiple components, each living in its own repository: a Bitcoin dev kit, an Ethereum dev kit, and a unified multi-chain block explorer that grows as each chain is added. The spirit of the entire project is one coherent idea — that a developer should be able to clone it, run it, and have the full vertical stack of a blockchain network in front of them, from the lowest level to the interface.

---

## Stack

| Layer | Module | Technology |
|---|---|---|
| Node infrastructure | `bitcoin-node` | Bitcoin Core 30.2 + Nginx + Docker |
| Shared utilities | `core/` | Python — crypto, RPC, config |
| Key derivation | `bitcoin-wallet` | Python — BIP-39, BIP-32, BIP-44 from scratch |
| RPC client | `bitcoin-client` | Python — JSON-RPC over HTTP |
| Transaction construction | `bitcoin-transactions` | Python — raw serialization, sighash, signing |
| Interface | `bitcoin-gui` | React 19 + Vite |

---

## Architecture

```
bitcoin-dev-kit/
 bitcoin-node/           Dockerized Bitcoin Core + Nginx load balancer
 core/                   Shared crypto primitives, RPC factory, config
 bitcoin-wallet/         BIP-39/32/44 HD wallet — no external wallet lib
 bitcoin-client/         Python RPC client for the node
 bitcoin-transactions/   Raw transaction templates — Legacy, SegWit, Taproot
 bitcoin-gui/            React dashboard — block explorer, RPC runner
 tests/                  Unit tests — no node required
```

All Python modules share a single virtual environment at the project root. `core/` is the shared foundation imported by every Python module — nothing is redefined or duplicated elsewhere.

---

## Prerequisites

- Docker + Docker Compose
- Python 3.10+
- Node.js 18+
- Bitcoin Core 30.2 binaries — download from [bitcoincore.org](https://bitcoincore.org/en/download/), extract, and place the version folder (`bitcoin-30.2`) into `bitcoin-node/dockerfile/bitcoin-node/`

> If your Bitcoin Core version differs from 30.2, update the version string in `bitcoin-node/dockerfile/bitcoin-node/Dockerfile` and in `bitcoin-node/docker-compose.yaml`.

---

## Setup

### 1. Clone

```bash
git clone https://github.com/Rhaytou/bitcoin-dev-kit.git
cd bitcoin-dev-kit
```

### 2. Configure environment variables

Copy and fill in the root environment file:

```bash
cp .env.example .env
```

Copy and fill in the GUI environment file:

```bash
cp bitcoin-gui/.env.example bitcoin-gui/.env
```

> Never commit `.env` files — they are gitignored by default.

**Root `.env`**

```
BTC_RPC_USER=your_rpc_username
BTC_RPC_PASS=your_rpc_password
BTC_RPC_ENDPOINT=http://localhost:8001
BTC_NETWORK=regtest
```

**`bitcoin-gui/.env`**

```
VITE_RPC_USER=your_rpc_username
VITE_RPC_PASS=your_rpc_password
VITE_RPC_ENDPOINT=http://localhost:8001
```

> The credentials you set here must match `rpcuser` and `rpcpassword` in `bitcoin-node/dockerfile/bitcoin-node/bitcoin.conf`.

### 3. Python environment

Set up once from the project root:

```bash
python3 -m venv envName
source envName/bin/activate
pip install -r requirements.txt
```

---

## Running

### bitcoin-node

Start the Bitcoin Core node and Nginx load balancer:

```bash
cd bitcoin-node
make up
```

Verify the node is running:

```bash
curl -u <rpcuser>:<rpcpassword> -X POST http://localhost:8001 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"1.0","id":"curl","method":"getblockchaininfo","params":[]}'
```

Available Makefile commands:

```bash
make up                # Start node + load balancer
make down              # Stop and remove containers
make docker_clean_all  # Full Docker cleanup
make bn_bash           # Open shell inside the bitcoin node container
make bn_logs           # Show bitcoin node logs
make nlb_logs          # Show load balancer logs
```

> The node runs in **regtest** mode by default. To switch networks, edit `bitcoin-node/dockerfile/bitcoin-node/bitcoin.conf` and update the nginx upstream port accordingly.

### bitcoin-wallet

BIP-39/32/44 HD wallet implemented from scratch — no external wallet library. Run from the project root with the virtual environment active:

```bash
python3 bitcoin-wallet/wallet.py
```

To create a new wallet, uncomment `bip39.create_wallet(...)` in `main()`. The wallet is saved as an AES-CBC encrypted, Base64-encoded `.wallet` file under `bitcoin-wallet/wallets/`.

> The AES key and IV in `main()` are hardcoded placeholders for demonstration. In production, derive the key from a user passphrase using PBKDF2, scrypt, or Argon2, and use a random IV per encryption.

### bitcoin-client

Python JSON-RPC client. Requires a running node:

```bash
python3 bitcoin-client/client.py
```

### bitcoin-transactions

Raw transaction construction and signing. Requires a running node. The `p2pkh_temp()` function automatically mines 500 blocks to the sender address to fund it — no manual funding required:

```bash
python3 bitcoin-transactions/tx_templates.py
```

Transaction types implemented and planned:

```
Legacy      P2PKH — implemented
            P2PK, Bare Multisig, P2SH, OP_RETURN, Coinbase — stubbed
SegWit v0   P2WPKH, P2WSH, P2SH-P2WPKH, P2SH-P2WSH — stubbed
Taproot     P2TR key-path / script-path — stubbed
```

### bitcoin-gui

React 19 + Vite dashboard. Requires a running node and a populated `bitcoin-gui/.env`:

```bash
cd bitcoin-gui
npm install
npm run dev
```

The dashboard exposes a block explorer with auto-detection of query type:

- Integer → `getblockhash`
- 64-char hex → `getblock`
- Anything else → `scantxoutset`

It also includes a dropdown to run any built-in no-argument RPC method directly.

---

## Tests

Unit tests only — no node required. Covers `core/crypto`, `bitcoin-wallet`, `bitcoin-transactions`, and `bitcoin-gui/src/scripts`.

**Python — from the project root with `envName` activated:**

```bash
pytest tests/
```

**JavaScript — from `bitcoin-gui/`:**

```bash
npm test
```

---

## Run Order

```
bitcoin-node → bitcoin-wallet → bitcoin-client → bitcoin-transactions → bitcoin-gui
```

Each layer depends on the one before it being available. You can run any layer in isolation — just be aware of what it expects.




