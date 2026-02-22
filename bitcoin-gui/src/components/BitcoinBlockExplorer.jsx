import { useState, useMemo } from "react";
import './styles/bitcoinblockexplorer.css';
import BitcoinRPC from "../scripts/bitcoin_client.js";
import RPC_AUTH_BTC from "../scripts/auth.js";

function BitcoinBlockExplorer() {
    const RPC        = useMemo(() => new BitcoinRPC("http://localhost:8001", RPC_AUTH_BTC), []);
    const rpcMethods = useMemo(() => RPC.getMethods(), [RPC]);

    const [query, setQuery]                   = useState("");
    const [result, setResult]                 = useState(null);
    const [error, setError]                   = useState(null);
    const [loading, setLoading]               = useState(false);
    const [selectedMethod, setSelectedMethod] = useState("getblockchaininfo");

    // Reset output before each new call
    function reset() {
        setResult(null);
        setError(null);
    }

    // Detect query type and map to the correct RPC call
    // height: getblockhash -> {"jsonrpc": "2.0", "id": "curltest", "method": "getblockhash", "params": [1000]}
    // blockhash: getblock -> {"jsonrpc": "2.0", "id": "curltest", "method": "getblock", "params": ["00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", 2]}
    // address and scripts: scantxoutset -> {"jsonrpc": "2.0", "id": "curltest", "method": "scantxoutset", "params": ["start", ["addr(msRbnS9guQPhdme657bTGTcr5PEhThM3yJ)"]]}
    function detectAndCall(query) {
        const trimmed = query.trim();

        // Height: pure integer
        if (/^\d+$/.test(trimmed)) {
            return RPC.call("getblockhash", [parseInt(trimmed)]);
        }

        // Block hash: 64 hex characters
        if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
            return RPC.call("getblock", [trimmed, 2]);
        }

        // Address or script: everything else goes to scantxoutset
        return RPC.call("scantxoutset", ["start", [`addr(${trimmed})`]]);
    }

    async function handleSearch(e) {
        e.preventDefault();
        if (!query.trim()) return;
        reset();
        setLoading(true);
        try {
            const data = await detectAndCall(query);
            setResult(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    async function handleMethod(e) {
        e.preventDefault();
        reset();
        setLoading(true);
        try {
            const data = await rpcMethods[selectedMethod]();
            setResult(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <section id="bitcoinblockexplorer">
            <h2>Bitcoin Block Explorer</h2>

            {/* Forms */}
            <section id="bbe-forms">

                {/* Search by hash / height / address / pubkey / script */}
                <form className="bbe-form" onSubmit={handleSearch}>
                    <label htmlFor="bbe-search">Search</label>
                    <input
                        id="bbe-search"
                        type="text"
                        placeholder="Height, Block hash, address, script…"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                    />
                    <button type="submit">Search</button>
                </form>

                {/* Built-in RPC method runner */}
                <form className="bbe-form" onSubmit={handleMethod}>
                    <label htmlFor="bbe-method">RPC Method</label>
                    <select
                        id="bbe-method"
                        value={selectedMethod}
                        onChange={(e) => setSelectedMethod(e.target.value)}
                    >
                        {Object.keys(rpcMethods).map((m) => (
                            <option key={m} value={m}>{m}</option>
                        ))}
                    </select>
                    <button type="submit">Run</button>
                </form>

            </section>

            {/* Result */}
            <section id="bbe-result">
                {loading && <p className="bbe-status">Loading…</p>}
                {error   && <p className="bbe-status bbe-error">{error}</p>}
                {result  && <pre>{JSON.stringify(result, null, 4)}</pre>}
            </section>

        </section>
    );
}

export default BitcoinBlockExplorer;





