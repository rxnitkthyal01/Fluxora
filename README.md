# Fluxora

Fluxora is a local developer workspace for declarative REST mocks, API request inspection, webhook capture, scenario simulation, and request history. It uses React and TypeScript in the browser, an Express API, and SQLite persistence through `sql.js` WebAssembly. Mock configurations are JSON data; user supplied JavaScript is never executed.

## Features

- Create and manage GET, POST, PUT, and DELETE mock routes.
- Configure JSON responses, status codes, response headers, delays, and timeout simulation.
- Define request-count response sequences and conditions on method, query parameters, headers, and JSON body fields.
- Browse generated API documentation and copy example cURL commands.
- Generate private webhook URLs, inspect incoming requests in real time, and revoke receiver URLs.
- Search and filter request history; sensitive headers and bearer webhook paths are redacted in API responses.
- Replay captured webhook requests to public HTTP(S) destinations only. DNS is checked again before connecting, and redirects are not followed.
- Customize the workspace name, opening section, refresh interval, and webhook notifications. These preferences are saved in the current browser.

## Requirements

- Node.js 20 or newer
- npm 10 or newer

`sql.js` bundles its SQLite engine as WebAssembly, so installing dependencies does not require a native C++ toolchain.

## Local development

```sh
npm install
cp .env.example .env
npm run dev
```

In Windows PowerShell, use `Copy-Item .env.example .env`. Open <http://127.0.0.1:5173>. Without seeded admin credentials, first launch asks you to create an administrator account. Otherwise, sign in with the credentials configured in `.env`. Later sign-ups are regular users. The API listens on <http://127.0.0.1:3001> and Vite proxies `/api`, `/mock`, and `/hooks` to it.

The database schema and indexes are initialized automatically. SQLite data is stored at `./data/fluxora.sqlite` by default and persists between runs.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3001` | Express API port |
| `HOST` | `127.0.0.1` | API bind address. Keep loopback for a local-only workspace. |
| `DATABASE_PATH` | `./data/fluxora.sqlite` | SQLite file path; use `:memory:` for an in-memory database |
| `FLUXORA_ENCRYPTION_KEY` | generated local key | 32-byte key as 64 hexadecimal characters for encrypting stored endpoint configs and request data. Required for non-loopback binds. |
| `FLUXORA_KEY_DIRECTORY` | OS user config directory | Optional directory for the generated encryption key |
| `FLUXORA_AUTH_SETUP_KEY` | unset | Optional setup key for first-account setup when no environment-seeded administrator exists |
| `FLUXORA_ADMIN_USERNAME` | unset | Optional administrator username used for one-time local bootstrap |
| `FLUXORA_ADMIN_PASSWORD` | unset | One-time bootstrap password; after first successful startup, remove this plaintext value from `.env` |
| `CLIENT_ORIGIN` | local Vite origins | Comma-separated browser origins allowed by CORS |
| `ALLOWED_HOSTS` | local hostnames | Comma-separated Host header allowlist |
| `COOKIE_SECURE` | `false` | Must be `true` for non-loopback deployments behind HTTPS |
| `TRUST_PROXY` | unset | Set to `1` only behind a trusted proxy that sanitizes forwarded headers |
| `MAX_DELAY_MS` | `10000` | Maximum configured mock response delay |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window in milliseconds |
| `RATE_LIMIT_MAX` | `120` | Maximum requests per IP per window |

The API binds to loopback (`127.0.0.1`) by default. The configured administrator is the only admin and lands on the Admin Panel. Later sign-ups are regular users and cannot be promoted to admin. Workspace data is shared across accounts. Mock execution routes and tokenized webhook receiver URLs stay public by design.

To provision an admin login from configuration, set `FLUXORA_ADMIN_USERNAME` and `FLUXORA_ADMIN_PASSWORD` for the first successful server startup. Fluxora stores a salted scrypt hash in SQLite, never the password itself. Once startup succeeds, remove the `FLUXORA_ADMIN_PASSWORD` line from `.env`; the account continues to work from its stored hash. Passwords must be 12–128 characters and include at least three of lowercase, uppercase, number, and symbol. Keep `.env` private and out of version control. If these variables are absent, the first account created in the app becomes the administrator; later registrations are regular users. For non-loopback deployments, inject bootstrap and encryption secrets from a deployment secret manager, and configure `HOST`, `ALLOWED_HOSTS`, `CLIENT_ORIGIN`, and `FLUXORA_ENCRYPTION_KEY`. Set `COOKIE_SECURE=true` and `TRUST_PROXY=1` only behind a trusted HTTPS reverse proxy. Keep the UI and API behind the same HTTPS origin or same-site reverse proxy.

## Try Fluxora

1. Open **API Builder**, create a route such as `GET /users`, and set its JSON response.
2. Open **API Reference** to inspect the generated URL and copy a cURL example. The mock URL is `http://127.0.0.1:5173/mock/users`.
3. Configure a response sequence on an endpoint to return `202` on its first request and `200` on the next. The final sequence item repeats until reset.
4. Set a timeout in the endpoint editor to simulate a client-side network failure. HTTP 429 and 500 settings return ordinary HTTP responses.
5. Open **Webhooks**, generate a private URL, and send it a request. Incoming events appear over SSE. The full token is shown once; revoke the receiver in the Webhooks section when it is no longer needed.
6. Inspect API calls and webhook events in **History**. Click a record for request and response details. Replay a webhook only to a public HTTP(S) destination you control.

Example request:

```sh
curl -X POST http://127.0.0.1:5173/mock/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Taylor"}'
```

## HTTP API

| Method and path | Purpose |
| --- | --- |
| `GET /api/health` | API health check |
| `GET /api/auth/status` | Check whether initial owner setup is needed |
| `POST /api/auth/setup` | Create the one-time owner account and start a session |
| `POST /api/auth/register` | Create a regular user account |
| `POST /api/auth/login` | Sign in and set an HttpOnly session cookie |
| `GET /api/auth/me` | Get the current session identity |
| `POST /api/auth/logout` | Revoke the current session |
| `GET /api/admin/users` | List accounts (admin only) |
| `PATCH /api/admin/users/:id` | Reject attempts to create another administrator (admin only) |
| `DELETE /api/admin/users/:id` | Delete an account (admin only) |
| `GET/POST /api/endpoints` | List or create mock endpoints |
| `PUT/DELETE /api/endpoints/:id` | Update or delete an endpoint |
| `POST /api/endpoints/:id/reset` | Reset a response sequence |
| `GET /api/history` | Search and filter captured request history |
| `POST /api/webhooks` | Create a private webhook receiver; returns its URL once |
| `GET /api/webhook-endpoints` | List receiver metadata without exposing tokens |
| `DELETE /api/webhook-endpoints/:id` | Revoke a receiver URL |
| `GET /api/webhooks` | List captured webhook events |
| `POST /api/webhooks/:id/replay` | Replay a captured request to a validated public destination |
| `GET /api/events` | SSE stream for webhook and dashboard updates |
| `ALL /hooks/:token` | Receive a webhook request |
| `ALL /mock/*` | Execute a configured mock route |

All workspace `/api` routes require the session cookie, except health and the documented account setup/sign-in routes. Webhook receiver and mock execution URLs are capability URLs by design.

## Tests and production build

```sh
npm test
npm run build
```

Tests use an in-memory SQLite database and do not contact external services. `npm start` starts the API server. For a production frontend build, serve `dist/` from a static server configured to proxy `/api`, `/mock`, and `/hooks` to the local Express API.

## Security and data handling

- Request bodies are limited to 256 KB. API routes have configurable per-IP rate limiting.
- Workspace APIs use salted scrypt password hashes, random server-side session tokens stored as hashes, 12-hour expiry, HttpOnly/SameSite cookies, logout revocation, and sign-in throttling by IP and account/IP pair. Configured bootstrap credentials are applied once; any extra admins are demoted, then the plaintext password can be removed from `.env`. Later registrations always receive the regular-user role. Login throttles are in-memory and reset when the local server restarts; keep Fluxora bound to loopback for local development.
- The default server binds to loopback. Host and browser Origin allowlists are checked before routing requests.
- Mock response/scenario configuration, request/response history, and webhook capture data are encrypted at rest with AES-256-GCM. For local use, Fluxora creates a random key in the OS user config directory, separate from the database. Non-loopback binds require `FLUXORA_ENCRYPTION_KEY`, which should be injected from a deployment secret manager. Back up the key with the database; changing or losing it makes encrypted records unreadable. Existing plaintext records are encrypted automatically at startup.
- Webhook bearer tokens contain 256 bits of random data. Only a SHA-256 token hash is stored; receiver records can be revoked. Never share the URL publicly.
- History output uses normalized key-name detection, recursive JSON inspection, credential-pattern scrubbing, URL query redaction, and webhook token masking. Redaction is best-effort: avoid sending production secrets through a mock workspace. Raw webhook bodies are encrypted at rest so explicit replay can preserve the original request; keep the database and encryption key private.
- Replay only allows HTTP(S), blocks private/reserved destinations, checks DNS again, pins a resolved public address, and does not follow redirects.
- Application host and origin checks do not install or change Windows Firewall rules. Network exposure still depends on firewall rules and a correctly configured HTTPS reverse proxy.
- At-rest encryption protects a database file copied without its key. It does not encrypt traffic between a browser and the server; remote use must terminate HTTPS at a trusted proxy. Mock routes intentionally return their configured responses to callers.

## Troubleshooting

- If startup cannot find `sql-wasm.wasm`, reinstall dependencies with `npm install`.
- If the dashboard cannot reach the API, check that port 3001 is available and that the browser URL matches `CLIENT_ORIGIN`.
- If a webhook URL has been lost, generate a new one. The token is intentionally not recoverable from the database; old receivers can still be revoked from the Webhooks section.
- If replay is rejected, use an HTTP(S) destination that resolves only to public addresses. Localhost, private IPs, reserved ranges, and redirects are blocked.
- Runtime SQLite files are stored under `data/` and excluded from version control.
