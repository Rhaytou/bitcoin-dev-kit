import json
import requests
from requests.auth import HTTPBasicAuth


# Rpc client
class BitcoinRPC:
    """JSON-RPC client for communicating with a Bitcoin node."""

    def __init__(self, endpoint: str, session: requests.Session, timeout: int = 30):
        """Set up the RPC connection with endpoint, session, and optional timeout."""
        self._url = endpoint
        self._session = session
        self._timeout = timeout
        self._session.headers.update({
            "Content-Type": "application/json"
        })

    def call(self, method: str, params=None, request_id="ipython"):
        """Send a JSON-RPC request and return the result. Raises on HTTP or RPC errors."""
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

    def getblockchaininfo(self):
        """Shortcut for the getblockchaininfo RPC call."""
        return self.call("getblockchaininfo")
''' '''
RPC_SESSION_BTC = requests.Session()
RPC_SESSION_BTC.auth = HTTPBasicAuth("slimane", "lbhvRHmyFA76TPab67Mzu3SlCKEokOc0xNUs2")
RPC_BTC_NGINX = BitcoinRPC(endpoint="http://localhost:8001", session=RPC_SESSION_BTC)
print(RPC_BTC_NGINX.getblockchaininfo())

command_var = RPC_BTC_NGINX.call("getblockchaininfo", [])
command_var_final = json.dumps(command_var, indent=4)
print(command_var_final)


# RPC commands
## Blockchain
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

## Control
'''
getmemoryinfo
getrpcinfo
help
logging
stop
uptime
'''

## Mining
'''
getblocktemplate
getmininginfo
getnetworkhashps
getprioritisedtransactions
prioritisetransaction
submitblock
submitheader
'''

## Network
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

## Rawtransactions
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

## Signer
'''
enumeratesigners
'''

## Util
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

## Wallet
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

## zmq
'''
getzmqnotifications
'''























