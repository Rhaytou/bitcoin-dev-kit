"""
bitcoin-client/client.py
========================
Thin re-export of core.rpc for the bitcoin-client module.

The BitcoinRPC class and get_rpc_client() factory now live in core/rpc.py.
This file exists so the bitcoin-client module remains a usable entry point
and so running `python3 client.py` directly still works.

Importing from this module:
    from core.rpc import BitcoinRPC, get_rpc_client
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.rpc import BitcoinRPC, get_rpc_client


# ---------------------------------------------------------------------------
# Entry point — only runs when executed directly, never on import
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rpc = get_rpc_client()

    info = rpc.getblockchaininfo()
    print(json.dumps(info, indent=4))


# ---------------------------------------------------------------------------
# RPC commands
# ---------------------------------------------------------------------------
# Blockchain
'''
getblockchaininfo
getbestblockhash
getblockcount
getblockhash
getchainstates
getchaintips
getblockheader
getblock
getblockfilter
getblockfrompeer
getblockstats
dumptxoutset
getchaintxstats
getdeploymentinfo
getdescriptoractivity
getdifficulty
getmempoolancestors
getmempooldescendants
getmempoolentry
getmempoolinfo
getrawmempool
gettxout
gettxoutproof
gettxoutsetinfo
gettxspendingprevout
importmempool
loadtxoutset
preciousblock
pruneblockchain
savemempool
scanblocks
scantxoutset
verifychain
verifytxoutproof
waitforblock
waitforblockheight
waitfornewblock
'''

# Control
'''
getmemoryinfo
getrpcinfo
help
logging
stop
uptime
'''

# Mining
'''
getblocktemplate
getmininginfo
getnetworkhashps
getprioritisedtransactions
prioritisetransaction
submitblock
submitheader
'''

# Network
'''
addnode
clearbanned
disconnectnode
getaddednodeinfo
getaddrmaninfo
getconnectioncount
getnettotals
getnetworkinfo
getnodeaddresses
getpeerinfo
listbanned
ping
setban
setnetworkactive
'''

# Rawtransactions
'''
descriptorprocesspsbt
combinerawtransaction
createrawtransaction
decoderawtransaction
fundrawtransaction
getrawtransaction
sendrawtransaction
signrawtransactionwithkey
decodescript
analyzepsbt
combinepsbt
converttopsbt
createpsbt
decodepsbt
finalizepsbt
joinpsbts
utxoupdatepsbt
submitpackage
testmempoolaccept
'''

# Signer
'''
enumeratesigners
'''

# Util
'''
createmultisig
deriveaddresses
estimatesmartfee
getdescriptorinfo
getindexinfo
signmessagewithprivkey
validateaddress
verifymessage
'''

# Wallet
'''
abandontransaction
abortrescan
backupwallet
bumpfee
createwallet
createwalletdescriptor
encryptwallet
getaddressesbylabel
getaddressinfo
getbalance
getbalances
gethdkeys
getnewaddress
getrawchangeaddress
getreceivedbyaddress
getreceivedbylabel
gettransaction
getwalletinfo
importdescriptors
importprunedfunds
keypoolrefill
listaddressgroupings
listdescriptors
listlabels
listlockunspent
listreceivedbyaddress
listreceivedbylabel
listsinceblock
listtransactions
listunspent
listwalletdir
listwallets
loadwallet
lockunspent
migratewallet
psbtbumpfee
removeprunedfunds
rescanblockchain
restorewallet
send
sendall
sendmany
sendtoaddress
setlabel
settxfee
setwalletflag
signmessage
signrawtransactionwithwallet
simulaterawtransaction
unloadwallet
walletcreatefundedpsbt
walletdisplayaddress
walletlock
walletpassphrase
walletpassphrasechange
walletprocesspsbt
'''

# zmq
'''
getzmqnotifications
'''























