/**
 * bitcoin-gui/src/scripts/bitcoin_client.js
 * ==========================================
 * Browser-side JSON-RPC client for communicating with a Bitcoin node.
 *
 * Credentials are injected via auth.js, which reads from Vite env vars.
 * Never instantiate BitcoinRPC with hardcoded credentials.
 *
 * Usage:
 *   import BitcoinRPC from "./bitcoin_client.js";
 *   import RPC_AUTH_BTC from "./auth.js";
 *
 *   const rpc = new BitcoinRPC(RPC_AUTH_BTC.endpoint, RPC_AUTH_BTC);
 *   const info = await rpc.getblockchaininfo();
 */

class BitcoinRPC {
    /**
     * @param {string} endpoint  - Full URL of the Bitcoin node RPC endpoint.
     * @param {object} auth      - Object with username and password fields.
     * @param {number} timeout   - Request timeout in milliseconds. Default: 30000.
     */
    constructor(endpoint, auth, timeout = 30000) {
        this._url     = endpoint;
        this._auth    = auth;
        this._timeout = timeout;
        this._headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + btoa(`${auth.username}:${auth.password}`),
        };
    }

    /**
     * Send a JSON-RPC request and return the result.
     *
     * @param {string} method    - Bitcoin RPC method name.
     * @param {Array}  params    - Positional parameters. Default: [].
     * @param {string} requestId - Arbitrary ID echoed back by the node.
     * @returns {Promise<*>}     - The result field of the JSON-RPC response.
     * @throws {Error}           - On HTTP errors or RPC-level errors.
     */
    async call(method, params = [], requestId = "bitcoin-dev-kit") {
        const payload = {
            jsonrpc: "2.0",
            id: requestId,
            method,
            params,
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

    // ------------------------------------------------------------------
    // Convenience shortcuts
    // ------------------------------------------------------------------

    async getblockchaininfo() { return this.call("getblockchaininfo"); }
    async getdeploymentinfo()  { return this.call("getdeploymentinfo"); }
    async verifychain()        { return this.call("verifychain"); }
    async getchainstates()     { return this.call("getchainstates"); }
    async getchaintips()       { return this.call("getchaintips"); }
    async getdifficulty()      { return this.call("getdifficulty"); }
    async getmempoolinfo()     { return this.call("getmempoolinfo"); }
    async getrawmempool()      { return this.call("getrawmempool"); }
    async getblockcount()      { return this.call("getblockcount"); }
    async getbestblockhash()   { return this.call("getbestblockhash"); }

    /**
     * Returns all built-in shortcut methods as callable entries.
     * Useful for dynamic dispatch in the dashboard.
     */
    getMethods() {
        return {
            getblockchaininfo: () => this.getblockchaininfo(),
            getdeploymentinfo: () => this.getdeploymentinfo(),
            verifychain:       () => this.verifychain(),
            getchainstates:    () => this.getchainstates(),
            getchaintips:      () => this.getchaintips(),
            getdifficulty:     () => this.getdifficulty(),
            getmempoolinfo:    () => this.getmempoolinfo(),
            getrawmempool:     () => this.getrawmempool(),
            getblockcount:     () => this.getblockcount(),
            getbestblockhash:  () => this.getbestblockhash(),
        };
    }
}

export default BitcoinRPC;