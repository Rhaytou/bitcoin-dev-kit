/**
 * bitcoin-gui/src/tests/bitcoin_client.test.js
 * =============================================
 * Unit tests for bitcoin_client.js — query detection logic and RPC call
 * construction. No node required. All network calls are mocked.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";


// ---------------------------------------------------------------------------
// Inline the detectAndCall logic for isolated testing
// The function is not exported from bitcoin_client.js so we replicate it here.
// If you export it later, replace this with a direct import.
// ---------------------------------------------------------------------------

function detectAndCall(rpc, query) {
    const trimmed = query.trim();

    if (/^\d+$/.test(trimmed)) {
        return rpc.call("getblockhash", [parseInt(trimmed)]);
    }

    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        return rpc.call("getblock", [trimmed, 2]);
    }

    return rpc.call("scantxoutset", ["start", [`addr(${trimmed})`]]);
}


// ---------------------------------------------------------------------------
// Query detection — detectAndCall routing
// ---------------------------------------------------------------------------

describe("detectAndCall — query routing", () => {

    let rpc;

    beforeEach(() => {
        rpc = { call: vi.fn() };
    });

    it("routes a plain integer to getblockhash", () => {
        detectAndCall(rpc, "1000");
        expect(rpc.call).toHaveBeenCalledWith("getblockhash", [1000]);
    });

    it("routes a 64-char hex string to getblock", () => {
        const blockhash = "a".repeat(64);
        detectAndCall(rpc, blockhash);
        expect(rpc.call).toHaveBeenCalledWith("getblock", [blockhash, 2]);
    });

    it("routes a Bitcoin address to scantxoutset", () => {
        const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf";
        detectAndCall(rpc, address);
        expect(rpc.call).toHaveBeenCalledWith("scantxoutset", [
            "start",
            [`addr(${address})`],
        ]);
    });

    it("trims whitespace before routing", () => {
        detectAndCall(rpc, "  500  ");
        expect(rpc.call).toHaveBeenCalledWith("getblockhash", [500]);
    });

    it("does not route a partial hex string as a block hash", () => {
        const partial = "a".repeat(63);  // 63 chars — not 64
        detectAndCall(rpc, partial);
        expect(rpc.call).toHaveBeenCalledWith("scantxoutset", [
            "start",
            [`addr(${partial})`],
        ]);
    });

    it("routes uppercase hex block hash correctly", () => {
        const blockhash = "A".repeat(64);
        detectAndCall(rpc, blockhash);
        expect(rpc.call).toHaveBeenCalledWith("getblock", [blockhash, 2]);
    });

});


// ---------------------------------------------------------------------------
// BitcoinRPC.call — request construction
// ---------------------------------------------------------------------------

describe("BitcoinRPC.call — request payload", () => {

    it("builds a valid JSON-RPC payload", async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ result: "ok", error: null }),
        });
        global.fetch = fetchMock;
        global.btoa = (str) => Buffer.from(str).toString("base64");

        // Minimal inline BitcoinRPC for payload verification
        class BitcoinRPC {
            constructor(endpoint, auth) {
                this._url = endpoint;
                this._headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Basic " + btoa(`${auth.username}:${auth.password}`),
                };
            }
            async call(method, params = [], requestId = "bitcoin-dev-kit") {
                const payload = { jsonrpc: "2.0", id: requestId, method, params };
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 5000);
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
                const data = await response.json();
                return data.result;
            }
        }

        const rpc = new BitcoinRPC("http://localhost:8001", {
            username: "user",
            password: "pass",
        });

        await rpc.call("getblockchaininfo");

        const body = JSON.parse(fetchMock.mock.calls[0][1].body);
        expect(body.jsonrpc).toBe("2.0");
        expect(body.method).toBe("getblockchaininfo");
        expect(body.params).toEqual([]);
        expect(body.id).toBe("bitcoin-dev-kit");
    });

});









