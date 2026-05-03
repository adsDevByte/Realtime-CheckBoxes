

const express = require("express");
const http    = require("http");
const WebSocket = require("ws");
const Redis   = require("ioredis");
const path    = require("path");
const crypto  = require("crypto");
const jwt     = require("jsonwebtoken");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, "../client")));

// ─── OIDC Config ──────────────────────────────────────────────────────────────

const PORT             = process.env.PORT            || 3001;
const OIDC_ISSUER      = process.env.OIDC_ISSUER     || "http://localhost:4000";
const OIDC_CLIENT_ID   = process.env.OIDC_CLIENT_ID  || "checkbox-app";
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || "checkbox-app-secret";
const APP_BASE_URL     = process.env.APP_BASE_URL    || `http://localhost:${PORT}`;
const REDIRECT_URI     = `${APP_BASE_URL}/callback`;

const pendingAuth = new Map();
let oidcDiscovery = null;
let jwksCache     = null;

async function fetchDiscovery() {
  if (oidcDiscovery) return oidcDiscovery;
  const res = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`);
  oidcDiscovery = await res.json();
  return oidcDiscovery;
}

async function fetchJWKS() {
  if (jwksCache) return jwksCache;
  const disc = await fetchDiscovery();
  const res  = await fetch(disc.jwks_uri);
  jwksCache  = await res.json();
  return jwksCache;
}

function jwkToPem(jwk) {
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return key.export({ type: "spki", format: "pem" });
}

async function verifyToken(token) {
  const jwks  = await fetchJWKS();
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
  const jwk   = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("No matching JWK");
  const pem = jwkToPem(jwk);
  return jwt.verify(token, pem, {
    algorithms: ["RS256"],
    issuer: OIDC_ISSUER,
    audience: OIDC_CLIENT_ID,
  });
}

// ─── OIDC Routes ──────────────────────────────────────────────────────────────

app.get("/login", async (req, res) => {
  try {
    const disc         = await fetchDiscovery();
    const codeVerifier = crypto.randomBytes(48).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const state        = crypto.randomBytes(16).toString("base64url");
    const nonce        = crypto.randomBytes(16).toString("base64url");

    pendingAuth.set(state, { codeVerifier, nonce });

    const authUrl = new URL(disc.authorization_endpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id",     OIDC_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri",  REDIRECT_URI);
    authUrl.searchParams.set("scope",         "openid profile email");
    authUrl.searchParams.set("state",         state);
    authUrl.searchParams.set("nonce",         nonce);
    authUrl.searchParams.set("code_challenge",        codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    res.redirect(authUrl.toString());
  } catch (err) {
    res.status(500).send("OIDC provider unavailable. Is it running on port 4000?");
  }
});

app.get("/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send("OIDC Error: " + error);

  const pending = pendingAuth.get(state);
  if (!pending) return res.status(400).send("Invalid or expired state.");
  pendingAuth.delete(state);

  try {
    const disc = await fetchDiscovery();
    const tokenRes = await fetch(disc.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type:    "authorization_code",
        code,
        redirect_uri:  REDIRECT_URI,
        client_id:     OIDC_CLIENT_ID,
        client_secret: OIDC_CLIENT_SECRET,
        code_verifier: pending.codeVerifier,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) return res.status(400).send("Token error: " + tokens.error);

    const claims = await verifyToken(tokens.id_token);

    res.send(`<!DOCTYPE html><html><head><title>Authenticated</title></head><body>
<script>
  localStorage.setItem("access_token", ${JSON.stringify(tokens.access_token)});
  localStorage.setItem("user", JSON.stringify({
    sub:   ${JSON.stringify(claims.sub)},
    name:  ${JSON.stringify(claims.name)},
    email: ${JSON.stringify(claims.email)}
  }));
  window.location.href = "/";
</script></body></html>`);
  } catch (err) {
    res.status(500).send("Authentication failed: " + err.message);
  }
});

app.get("/logout", async (req, res) => {
  try {
    const disc = await fetchDiscovery();
    const logoutUrl = new URL(disc.end_session_endpoint);
    logoutUrl.searchParams.set("post_logout_redirect_uri", `${APP_BASE_URL}/`);
    res.send(`<!DOCTYPE html><html><head><title>Logging out...</title></head><body>
<script>
  localStorage.removeItem("access_token");
  localStorage.removeItem("user");
  window.location.href = ${JSON.stringify(logoutUrl.toString())};
</script></body></html>`);
  } catch {
    res.send(`<!DOCTYPE html><html><body><script>localStorage.clear();window.location.href="/";</script></body></html>`);
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../client/index.html"));
});



const REDIS_HOST = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT = process.env.REDIS_PORT || 6379;
const REDIS_PASS = process.env.REDIS_PASSWORD || undefined;

const redisCfg = { host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASS };
const redis = new Redis(redisCfg);
const pub   = new Redis(redisCfg);
const sub   = new Redis(redisCfg);



const TOTAL = 10000;
let checkboxState = new Array(TOTAL).fill(0);

(async () => {
  const data = await redis.get("checkbox_state");
  if (data) checkboxState = JSON.parse(data);
})();


const rateLimitMap = new Map();
function isRateLimited(userId) {
  const now = Date.now();
  const entry = rateLimitMap.get(userId);
  if (!entry || now - entry.time > 1000) {
    rateLimitMap.set(userId, { count: 1, time: now });
    return false;
  }
  entry.count++;
  return entry.count > 10;
}


sub.subscribe("checkbox_updates");
sub.on("message", (_, message) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(message);
  });
});



wss.on("connection", async (ws, req) => {
  const url   = new URL(req.url, "http://localhost");
  const token = url.searchParams.get("token");
  if (!token) return ws.close(1008, "No token");

  let user;
  try {
    user = await verifyToken(token);
  } catch (err) {
    return ws.close(1008, "Auth failed");
  }

  ws.user = user;
  ws.send(JSON.stringify({ type: "init", state: checkboxState }));

  
  broadcastMeta();

  ws.on("close", () => broadcastMeta());

  ws.on("message", async (msg) => {
    let data;
    try { data = JSON.parse(msg); } catch { return; }

    if (isRateLimited(ws.user.sub)) return;

    checkboxState[data.index] = data.value;
    await redis.set("checkbox_state", JSON.stringify(checkboxState));
    pub.publish("checkbox_updates", JSON.stringify({
      type: "toggle",
      index: data.index,
      value: data.value,
      by: ws.user.name || ws.user.sub,
    }));
  });
});

function broadcastMeta() {
  const online = wss.clients.size;
  const checked = checkboxState.filter(Boolean).length;
  const msg = JSON.stringify({ type: "meta", online, checked });
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}



server.listen(PORT, () => console.log(`✅ Checkbox app running at ${APP_BASE_URL}`));
