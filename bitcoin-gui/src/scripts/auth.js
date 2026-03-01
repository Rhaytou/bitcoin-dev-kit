/**
 * bitcoin-gui/src/scripts/auth.js
 * ================================
 * RPC authentication config for the Bitcoin GUI.
 *
 * Credentials are read from Vite environment variables — never hardcoded.
 * Define the following in bitcoin-gui/.env (gitignored):
 *
 *   VITE_RPC_USER=your_rpc_username
 *   VITE_RPC_PASS=your_rpc_password
 *   VITE_RPC_ENDPOINT=http://localhost:8001
 *
 * Only variables prefixed with VITE_ are exposed to the browser bundle.
 * See bitcoin-gui/.env.example for a safe template to commit.
 *
 * NOTE: For production deployments, RPC calls should be proxied through a
 * backend server so credentials are never shipped to the client at all.
 * This approach (Vite env vars) is appropriate for local development only.
 */

const RPC_AUTH_BTC = {
    username: import.meta.env.VITE_RPC_USER,
    password: import.meta.env.VITE_RPC_PASS,
    endpoint: import.meta.env.VITE_RPC_ENDPOINT ?? "http://localhost:8001",
};

if (!RPC_AUTH_BTC.username || !RPC_AUTH_BTC.password) {
    throw new Error(
        "[bitcoin-gui] Missing RPC credentials.\n" +
        "Create bitcoin-gui/.env with VITE_RPC_USER and VITE_RPC_PASS.\n" +
        "Copy bitcoin-gui/.env.example to get started."
    );
}

export default RPC_AUTH_BTC;
