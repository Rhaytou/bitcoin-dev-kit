import RPC_AUTH_BTC from "./auth.js";

// Rpc client
class BitcoinRPC {
    /** JSON-RPC client for communicating with a Bitcoin node. */

    constructor(endpoint, auth, timeout = 30000) {
        /** Set up the RPC connection with endpoint, auth, and optional timeout. */
        this._url = endpoint;
        this._auth = auth;
        this._timeout = timeout;
        this._headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + btoa(`${auth.username}:${auth.password}`),
        };
    }

    async call(method, params = [], requestId = "ipython") {
        /** Send a JSON-RPC request and return the result. Raises on HTTP or RPC errors. */
        const payload = {
            jsonrpc: "2.0",
            id: requestId,
            method: method,
            params: params,
        };

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this._timeout);

        let response;
        try {
            response = await fetch(this._url, {
                method: "POST",
                headers: this._headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
        } finally {
            clearTimeout(timer);
        }

        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();

        if (data.error != null) {
            throw new Error(JSON.stringify(data.error));
        }

        return data.result;
    }

    async getblockchaininfo() {
        /** Shortcut for the getblockchaininfo RPC call. */
        return this.call("getblockchaininfo");
    }

    async getdeploymentinfo() {
        /** Shortcut for the getdeploymentinfo RPC call. */
        return this.call("getdeploymentinfo");
    }

    async verifychain() {
        /** Shortcut for the verifychain RPC call. */
        return this.call("verifychain");
    }

    async getchainstates() {
        /** Shortcut for the getchainstates RPC call. */
        return this.call("getchainstates");
    }

    async getchaintips() {
        /** Shortcut for the getchaintips RPC call. */
        return this.call("getchaintips");
    }

    async getdifficulty() {
        /** Shortcut for the getdifficulty RPC call. */
        return this.call("getdifficulty");
    }

    async getmempoolinfo() {
        /** Shortcut for the getmempoolinfo RPC call. */
        return this.call("getmempoolinfo");
    }

    async getrawmempool() {
        /** Shortcut for the getrawmempool RPC call. */
        return this.call("getrawmempool");
    }

    async getblockcount() {
        /** Shortcut for the getblockcount RPC call. */
        return this.call("getblockcount");
    }

    async getbestblockhash() {
        /** Shortcut for the getbestblockhash RPC call. */
        return this.call("getbestblockhash");
    }

    // Returns all built-in shortcut methods as callable entries
    getMethods() {
        return {
            getblockchaininfo: () => this.getblockchaininfo(),
            getdeploymentinfo: () => this.getdeploymentinfo(),
            verifychain:       () => this.verifychain(),
            getchainstates:    () => this.getchainstates(),
            getchaintips:      () => this.getchaintips(),
            getdifficulty:      () => this.getdifficulty(),
            getmempoolinfo:      () => this.getmempoolinfo(),
            getrawmempool:      () => this.getrawmempool(),
            getblockcount:      () => this.getblockcount(),
            getbestblockhash:      () => this.getbestblockhash()
        };
    }
}

export default BitcoinRPC;

/*
// Examples
const RPC_BTC_NGINX = new BitcoinRPC("http://localhost:8001", RPC_AUTH_BTC);

const getblockchaininfo = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getblockchaininfo);

const getdeploymentinfo = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getdeploymentinfo);

const verifychain = await RPC_BTC_NGINX.getblockchaininfo();
console.log(verifychain);

const getchainstates = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getchainstates);

const getchaintips = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getchaintips);

const getdifficulty = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getdifficulty);

const getmempoolinfo = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getmempoolinfo);

const getrawmempool = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getrawmempool);

const getblockcount = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getblockcount);

const getbestblockhash = await RPC_BTC_NGINX.getblockchaininfo();
console.log(getbestblockhash);

const commandVar = await RPC_BTC_NGINX.call("getblockchaininfo", []);
const commandVarFinal = JSON.stringify(commandVar, null, 4);
console.log(commandVarFinal);

const commandVar = await RPC_BTC_NGINX.call("generatetoaddress", [101, 'mvRvoTnFzyAPwuYZbPteBUXFhH6rj8hKXV']);
const commandVarFinal = JSON.stringify(commandVar, null, 4);
console.log(commandVarFinal);
*/






