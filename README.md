
# ☑️ Realtime Checkbox Collective

A collaborative real-time application where authenticated users share and toggle 10,000 checkboxes simultaneously — powered by Node.js, WebSockets, and Redis — secured with a fully self-hosted OpenID Connect (OIDC) provider implementing the Authorization Code + PKCE flow.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Tech Stack](#tech-stack)
- [Setup Steps](#setup-steps)
- [Environment Variables](#environment-variables)
- [OIDC Auth Setup](#oidc-auth-setup)
- [Socket Event Flow](#socket-event-flow)
- [Redis Pub/Sub Flow](#redis-pubsub-flow)
- [Assumptions and Limitations](#assumptions-and-limitations)

---

## Project Overview

Checkbox Collective renders a 100×100 grid of 10,000 checkboxes shared across every connected user. When any user toggles a checkbox, the change is published to Redis and broadcast in real time to every other connected browser — no page refresh required.

Authentication is handled by a self-hosted OIDC provider (included in this repo). Users can **register a new account** or **sign in** with an existing one directly on the OIDC login page. The provider issues RS256-signed JWTs that the app server verifies against the provider's public JWKS endpoint — no shared secret is needed between the two processes.

Checkbox state is persisted in Redis so that a freshly connected user immediately sees the current state of the grid rather than starting from scratch.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 18+ |
| Web framework | Express 4 |
| Real-time transport | WebSocket (`ws` library) |
| State persistence + pub/sub | Redis (`ioredis`) |
| Auth protocol | OpenID Connect 1.0 — Authorization Code + PKCE |
| Token format | JWT (RS256, verified via JWKS) |
| UI fonts | Space Mono + Syne (Google Fonts) |
| Containerisation | Docker (Redis only) |

---

## Setup Steps

### Prerequisites

- Node.js 18 or later
- Docker (for Redis)
- npm

### 1. Clone and install

```bash
git clone <your-repo-url>
cd realtime-checkbox-oidc
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Defaults work for local development — no changes required
```

### 3. Start Redis

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

### 4. Start the OIDC provider

```bash
# Terminal 1
node oidc-provider/index.js
# → 🔐 OIDC Provider running at http://localhost:4000
```

### 5. Start the app server

```bash
# Terminal 2
node server/index.js
# → ✅ Checkbox app running at http://localhost:3001
```

### 6. Open the app

Navigate to **http://localhost:3001** and click **Sign in to join**.

You can use a seeded demo account or create a new one directly on the login screen:

| Username | Password |
|---|---|
| adarsh | pass123 |
| demo | demo123 |

### Running both servers together

```bash
npm run dev   # starts OIDC provider + app server concurrently
```

> Redis must still be started separately as it is a standalone service.

---

## Environment Variables

### App server (`server/index.js`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3001` | Port the app server listens on |
| `APP_BASE_URL` | `http://localhost:3001` | Public base URL — used to construct the OIDC callback URI |
| `OIDC_ISSUER` | `http://localhost:4000` | Base URL of the OIDC provider |
| `OIDC_CLIENT_ID` | `checkbox-app` | Client ID registered in the OIDC provider |
| `OIDC_CLIENT_SECRET` | `checkbox-app-secret` | Client secret registered in the OIDC provider |
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | *(unset)* | Redis password (optional, for authenticated Redis instances) |

### OIDC provider (`oidc-provider/index.js`)

| Variable | Default | Description |
|---|---|---|
| `OIDC_PORT` | `4000` | Port the OIDC provider listens on |
| `OIDC_ISSUER` | `http://localhost:4000` | Issuer URL embedded in all issued tokens — must match `OIDC_ISSUER` in the app server |

---

## OIDC Auth Setup

### How it works

This project ships its own OpenID Connect provider. It implements the **Authorization Code flow with PKCE (Proof Key for Code Exchange)** and signs tokens with an RSA-256 key pair generated fresh on each provider startup.

The login page supports both **Sign In** (existing users) and **Register** (new account creation) via a tabbed interface. Newly registered users are stored in memory for the lifetime of the provider process.

```
Browser          App Server (3001)         OIDC Provider (4000)
  │                    │                         │
  │  GET /login        │                         │
  │──────────────────► │                         │
  │                    │  generate PKCE pair     │
  │                    │  state, nonce           │
  │  redirect 302      │                         │
  │◄───────────────────│                         │
  │                                              │
  │  GET /authorize?code_challenge=...           │
  │─────────────────────────────────────────────►│
  │                                              │  show login/register form
  │◄─────────────────────────────────────────────│
  │  POST credentials (login or register)        │
  │─────────────────────────────────────────────►│
  │                                              │  issue auth code
  │  redirect to /callback?code=...&state=...    │
  │◄─────────────────────────────────────────────│
  │                    │                         │
  │  GET /callback     │                         │
  │──────────────────► │                         │
  │                    │  POST /token            │
  │                    │  (code + code_verifier) │
  │                    │────────────────────────►│
  │                    │  { id_token,            │
  │                    │    access_token }       │
  │                    │◄────────────────────────│
  │                    │  verify id_token        │
  │                    │  via /jwks              │
  │  tokens stored in  │                         │
  │  localStorage      │                         │
  │◄───────────────────│                         │
```

### OIDC provider endpoints

| Endpoint | URL | Description |
|---|---|---|
| Discovery | `http://localhost:4000/.well-known/openid-configuration` | Lists all other endpoint URLs |
| Authorization | `http://localhost:4000/authorize` | Shows login/register form, issues auth code |
| Token | `http://localhost:4000/token` | Exchanges auth code for tokens |
| UserInfo | `http://localhost:4000/userinfo` | Returns profile claims for a Bearer token |
| JWKS | `http://localhost:4000/jwks` | Public RSA key set for token verification |
| Logout | `http://localhost:4000/logout` | Clears session and redirects |

### Token verification

The app server never shares a secret with the OIDC provider. Instead it fetches the provider's public RSA key from `/jwks` on first use, caches it, and uses it to verify every incoming JWT with `jwt.verify()`. This means any service that can reach the JWKS endpoint can independently validate tokens without any additional configuration.

### Adding a new client application

Edit the `CLIENTS` object in `oidc-provider/index.js`:

```js
"my-new-app": {
  clientSecret: "my-secret",
  redirectUris: ["http://localhost:5000/callback"],
  name: "My New App",
  icon: "🛠️",
  accentColor: "#a855f7",
}
```

### Adding or seeding users

Edit the `USERS` object in `oidc-provider/index.js`:

```js
newuser: {
  passwordHash: hashPassword("password123"),
  name: "New User",
  email: "new@example.com",
  createdAt: new Date().toISOString(),
},
```

> In production, replace SHA-256 password hashing with bcrypt or Argon2 and load users from a database.

---

## Socket Event Flow

Raw WebSockets (`ws` library) provide the real-time bidirectional channel. Every connection is authenticated before any events are processed.

### Authentication

The client appends the OIDC access token as a URL query parameter when opening the WebSocket connection:

```js
// Client side
const ws = new WebSocket(`ws://${location.host}?token=${accessToken}`);
```

The server reads the token from the request URL, verifies it against the OIDC JWKS, and either accepts or closes the connection with code `1008` (policy violation):

```
Client opens ws://localhost:3001?token=<jwt>
  └── server calls verifyToken(token)
        ├── fetches JWKS from http://localhost:4000/jwks
        ├── verifies RS256 signature, issuer, audience
        ├── attaches decoded claims to ws.user
        └── sends { type: "init", state: checkboxState }  →  connection accepted
        OR
        └── ws.close(1008, "Auth failed")  →  connection rejected
```

### Events

**Server → Client (on connect)**

| Message type | Payload | Description |
|---|---|---|
| `init` | `{ type: "init", state: number[] }` | Full array of 10,000 checkbox values (0 or 1), sent once immediately after a successful connection |
| `meta` | `{ type: "meta", online: number }` | Current count of connected users, sent on every connect or disconnect |

**Client → Server**

| Message type | Payload | Description |
|---|---|---|
| `toggle` | `{ type: "toggle", index: number, value: 0\|1 }` | Sent when the user clicks a checkbox |

**Server → All Clients (via Redis)**

| Message type | Payload | Description |
|---|---|---|
| `toggle` | `{ type: "toggle", index: number, value: 0\|1, by: string }` | Broadcast to every connected client when a toggle is published from Redis |

### Rate limiting

Each user is limited to **10 toggles per second** enforced server-side. Excess messages are silently dropped — no error is returned to the client.

### Full flow

```
Browser (user clicks checkbox i)
  │
  │  ws.send({ type: "toggle", index: i, value: 1 })
  ▼
App Server
  ├── rate-limit check (max 10/sec per userId)
  ├── checkboxState[i] = value
  ├── redis.set("checkbox_state", JSON.stringify(checkboxState))   ← persist
  └── pub.publish("checkbox_updates", JSON.stringify({ type, index, value, by }))
  │
  ▼
Redis pub/sub subscriber (same process)
  └── sub.on("message") fires
        └── broadcast to all ws clients
  │
  ▼
All connected browsers
  └── setCb(index, value)  →  re-render checkbox + flash animation
```

---

## Redis Pub/Sub Flow

Redis serves two roles: **state persistence** (so new connections see the current grid) and **pub/sub messaging** (so toggle events are distributed to all WebSocket clients).

Three separate `ioredis` connections are maintained:

| Connection | Variable | Role |
|---|---|---|
| Main | `redis` | `GET` / `SET` for checkbox state persistence |
| Publisher | `pub` | `PUBLISH` toggle events to `checkbox_updates` channel |
| Subscriber | `sub` | `SUBSCRIBE` to `checkbox_updates` and relay to WebSocket clients |

> Redis requires three separate connections because a client in subscriber mode cannot issue regular commands on the same connection.

### State persistence

On startup the server loads the saved state from Redis:

```js
const data = await redis.get("checkbox_state");
if (data) checkboxState = JSON.parse(data);
```

After every toggle the full state array is written back:

```js
await redis.set("checkbox_state", JSON.stringify(checkboxState));
```

### Pub/Sub message format

Every message published to the `checkbox_updates` channel is a JSON string:

```json
{
  "type": "toggle",
  "index": 4271,
  "value": 1,
  "by": "Adarsh"
}
```

### Flow diagram

```
Toggle event received from WebSocket
  │
  ├── redis.set("checkbox_state", fullStateArray)
  │
  └── pub.publish("checkbox_updates", toggleMessage)
        │
        ▼
   Redis broker (localhost:6379)
        │
        ▼
   sub.on("message", handler)
        │
        └── wss.clients.forEach → client.send(message)
              │
              ▼
        All connected browsers update the grid
```

---

## Assumptions and Limitations

### Assumptions

- The OIDC provider and app server run on the same machine during development. In production they would each have their own hostname and `OIDC_ISSUER` / `APP_BASE_URL` would be updated accordingly.
- Redis is available on `localhost:6379` with no authentication by default. Set `REDIS_PASSWORD` for secured instances.
- A single Redis instance is sufficient for development. For high-availability deployments, Redis Sentinel or Redis Cluster should be used.
- Users grant `localStorage` access. The app stores tokens in `localStorage` and will not function in browsers with storage disabled.

### Limitations

- **In-memory user store in the OIDC provider.** Registered users, auth codes, and refresh tokens are all held in memory. A provider restart clears all registered accounts except the seeded demo users. Production deployments must persist the user store in a database.
- **Tokens stored in `localStorage`.** Acceptable for local development but vulnerable to XSS attacks. Production deployments should use `HttpOnly`, `Secure` cookies instead.
- **JWKS cache is never invalidated.** The provider generates a new RSA key pair on every restart. If the provider restarts while the app server is running, the cached public key goes stale and all token verifications will fail until the app server is also restarted. A production implementation should refresh the JWKS cache on a verification failure.
- **Full state rewrite on every toggle.** Saving the entire 10,000-element array to Redis on each toggle is simple but inefficient at scale. A production implementation should store individual checkbox values using Redis bit fields (`SETBIT` / `GETBIT`).
- **No HTTPS.** All traffic is plain HTTP. Production deployments must terminate TLS in front of both servers.
- **SHA-256 password hashing.** The OIDC provider uses SHA-256 for password hashing, which is not suitable for production. Use bcrypt or Argon2 with an appropriate cost factor instead.
- **Single server, single pub/sub subscriber.** The `checkboxState` in-memory array is local to each process. Running multiple app server instances would cause state to drift between them. A production setup should treat Redis as the single source of truth and not maintain a local copy.
- **No token refresh.** Access tokens expire after one hour and the client does not automatically renew them. Users must log in again after expiry.
- **No rate limiting on auth endpoints.** The `/login` route and the OIDC `/authorize/submit` endpoint have no brute-force protection. Add `express-rate-limit` or a reverse-proxy-level rate limiter before exposing these publicly.
- **10,000 checkbox limit is hard-coded.** The `TOTAL` constant is defined independently in both the server and the client and must be kept in sync manually. It is not exposed as a configuration option.

