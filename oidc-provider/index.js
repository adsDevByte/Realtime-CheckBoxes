

const express = require("express");
const crypto  = require("crypto");
const jwt     = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT   = process.env.OIDC_PORT   || 4000;
const ISSUER = process.env.OIDC_ISSUER || `http://localhost:${PORT}`;


const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const jwkPublic = crypto.createPublicKey(publicKey).export({ format: "jwk" });
const KEY_ID    = crypto.randomBytes(8).toString("hex");

// ─── Clients ──────────────────────────────────────────────────────────────────
const CLIENTS = {
  "location-app": {
    clientSecret: process.env.OIDC_CLIENT_SECRET || "location-app-secret",
    redirectUris: ["http://localhost:3000/callback", "http://127.0.0.1:3000/callback"],
    name: "Live Tracker",
    icon: "📍",
    accentColor: "#4f8ef7",
  },
  "checkbox-app": {
    clientSecret: "checkbox-app-secret",
    redirectUris: ["http://localhost:3001/callback", "http://127.0.0.1:3001/callback"],
    name: "Checkbox Collective",
    icon: "☑️",
    accentColor: "#00e5ff",
  },
};

// ─── Users ────────────────────────────────────────────────────────────────────
function hashPassword(plain) {
  return crypto.createHash("sha256").update(plain).digest("hex");
}

const USERS = {
  adarsh: { passwordHash: hashPassword("pass123"), name: "Adarsh",    email: "adarsh@example.com", createdAt: new Date().toISOString() },
  demo:   { passwordHash: hashPassword("demo123"), name: "Demo User", email: "demo@example.com",   createdAt: new Date().toISOString() },
};

const authCodes     = new Map();
const refreshTokens = new Map();

// ─── Crypto helpers ───────────────────────────────────────────────────────────
const generateCode  = () => crypto.randomBytes(32).toString("base64url");
const generateToken = () => crypto.randomBytes(40).toString("base64url");

const signIdToken = (p) =>
  jwt.sign(p, privateKey, { algorithm: "RS256", keyid: KEY_ID });

const signAccessToken = (p) =>
  jwt.sign(p, privateKey, { algorithm: "RS256", keyid: KEY_ID, expiresIn: "1h" });

const verifyAccessToken = (t) =>
  jwt.verify(t, publicKey, { algorithms: ["RS256"] });

function verifyPKCE(verifier, challenge, method) {
  if (method === "S256")
    return crypto.createHash("sha256").update(verifier).digest("base64url") === challenge;
  return verifier === challenge;
}

// ─── Page renderer ────────────────────────────────────────────────────────────
function renderPage({ client, loginError, regError, registered, hiddenFields, prefillUsername }) {
  const showReg = !!(regError || registered);
  const accent  = client.accentColor;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Sign In — ${client.name}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@700;800&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:      #07090d;
      --surface: #0d1117;
      --card:    #111820;
      --border:  #1c2736;
      --accent:  ${accent};
      --accent2: #ff3d6b;
      --text:    #c9d8e8;
      --dim:     #3d5268;
      --glow:    color-mix(in srgb, ${accent} 20%, transparent);
    }

    html, body {
      height: 100%;
      background: var(--bg);
      color: var(--text);
      font-family: 'Space Mono', monospace;
    }

    /* ── Animated background grid ── */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background-image:
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
      background-size: 40px 40px;
      opacity: 0.35;
      pointer-events: none;
    }

    body::after {
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background: radial-gradient(ellipse 60% 50% at 50% 0%, color-mix(in srgb, ${accent} 12%, transparent), transparent 70%);
      pointer-events: none;
    }

    .wrap {
      position: relative; z-index: 1;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    /* ── Card ── */
    .card {
      width: 100%;
      max-width: 420px;
      background: var(--card);
      border: 1px solid var(--border);
      border-top: 1px solid color-mix(in srgb, ${accent} 30%, var(--border));
      border-radius: 4px;
      padding: 40px 36px 36px;
      box-shadow: 0 0 0 1px rgba(0,0,0,.5), 0 32px 64px rgba(0,0,0,.6), 0 0 80px var(--glow);
      animation: slideUp .4s cubic-bezier(.16,1,.3,1) both;
    }

    @keyframes slideUp {
      from { opacity: 0; transform: translateY(20px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    /* ── Header ── */
    .provider-tag {
      font-size: 9px;
      letter-spacing: 3px;
      text-transform: uppercase;
      color: var(--dim);
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .provider-tag::before, .provider-tag::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    .app-icon {
      font-size: 32px;
      text-align: center;
      margin-bottom: 8px;
      filter: drop-shadow(0 0 16px var(--glow));
    }

    .app-name {
      font-family: 'Syne', sans-serif;
      font-size: 20px;
      font-weight: 800;
      color: #fff;
      text-align: center;
      margin-bottom: 28px;
      letter-spacing: -0.3px;
    }

    /* ── Tabs ── */
    .tabs {
      display: grid;
      grid-template-columns: 1fr 1fr;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 3px;
      padding: 3px;
      gap: 3px;
      margin-bottom: 24px;
    }

    .tab {
      padding: 8px;
      border: none;
      border-radius: 2px;
      background: transparent;
      color: var(--dim);
      font-family: 'Space Mono', monospace;
      font-size: 11px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      cursor: pointer;
      transition: background .15s, color .15s;
    }

    .tab.active {
      background: color-mix(in srgb, ${accent} 15%, transparent);
      color: var(--accent);
    }

    /* ── Forms ── */
    .section { display: none; }
    .section.on { display: block; }

    label {
      display: block;
      font-size: 10px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--dim);
      margin-bottom: 6px;
    }

    input[type=text], input[type=email], input[type=password] {
      width: 100%;
      padding: 10px 14px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 3px;
      color: var(--text);
      font-family: 'Space Mono', monospace;
      font-size: 13px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color .15s, box-shadow .15s;
    }

    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--glow);
    }

    input::placeholder { color: var(--dim); }

    /* ── Alerts ── */
    .alert {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 10px 14px;
      border-radius: 3px;
      font-size: 12px;
      line-height: 1.5;
      margin-bottom: 16px;
    }

    .alert-err {
      background: rgba(255,61,107,.08);
      border: 1px solid rgba(255,61,107,.25);
      color: #ff8fa3;
    }

    .alert-ok {
      background: rgba(0,229,107,.08);
      border: 1px solid rgba(0,229,107,.25);
      color: #6efaad;
    }

    /* ── Submit button ── */
    .btn {
      width: 100%;
      padding: 12px;
      background: transparent;
      border: 1px solid var(--accent);
      color: var(--accent);
      font-family: 'Space Mono', monospace;
      font-size: 12px;
      letter-spacing: 2px;
      text-transform: uppercase;
      cursor: pointer;
      border-radius: 3px;
      position: relative;
      overflow: hidden;
      transition: color .2s;
    }

    .btn::before {
      content: '';
      position: absolute; inset: 0;
      background: var(--accent);
      transform: scaleX(0);
      transform-origin: left;
      transition: transform .2s ease;
      z-index: 0;
    }

    .btn:hover { color: var(--bg); }
    .btn:hover::before { transform: scaleX(1); }

    .btn span { position: relative; z-index: 1; }

    /* ── Scan line decoration ── */
    .scanline {
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
      margin: 20px 0;
      opacity: 0.4;
    }
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="provider-tag">OIDC Auth</div>
    <div class="app-icon">${client.icon}</div>
    <div class="app-name">${client.name}</div>

    <div class="tabs">
      <button class="tab ${!showReg ? "active" : ""}" data-t="login">Sign In</button>
      <button class="tab ${showReg  ? "active" : ""}" data-t="reg">Register</button>
    </div>

    <!-- LOGIN -->
    <div id="login" class="section ${!showReg ? "on" : ""}">
      ${loginError ? `<div class="alert alert-err">⚠ ${loginError}</div>` : ""}
      <form method="POST" action="/authorize/submit">
        ${hiddenFields}
        <label>Username</label>
        <input type="text" name="username" placeholder="your_username" value="${prefillUsername || ""}" autocomplete="username" required/>
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" required/>
        <button type="submit" class="btn"><span>Sign In →</span></button>
      </form>
    </div>

    <!-- REGISTER -->
    <div id="reg" class="section ${showReg ? "on" : ""}">
      ${regError   ? `<div class="alert alert-err">⚠ ${regError}</div>` : ""}
      ${registered ? `<div class="alert alert-ok">✓ Account created — switch to Sign In</div>` : ""}
      <form method="POST" action="/authorize/register">
        ${hiddenFields}
        <label>Full Name</label>
        <input type="text" name="name" placeholder="Jane Smith" autocomplete="name" required/>
        <label>Email</label>
        <input type="email" name="email" placeholder="jane@example.com" autocomplete="email" required/>
        <div class="scanline"></div>
        <label>Username</label>
        <input type="text" name="username" placeholder="janesmith" autocomplete="username" required/>
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" autocomplete="new-password" required/>
        <label>Confirm Password</label>
        <input type="password" name="confirm_password" placeholder="••••••••" autocomplete="new-password" required/>
        <button type="submit" class="btn"><span>Create Account →</span></button>
      </form>
    </div>
  </div>
</div>

<script>
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.t;
      document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.section').forEach(s => s.classList.toggle('on', s.id === t));
    });
  });
</script>
</body>
</html>`;
}

// ─── Discovery ────────────────────────────────────────────────────────────────
app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/logout`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "name", "email"],
    code_challenge_methods_supported: ["S256", "plain"],
    grant_types_supported: ["authorization_code", "refresh_token"],
  });
});

app.get("/jwks", (_req, res) => {
  res.json({ keys: [{ kty: jwkPublic.kty, use: "sig", alg: "RS256", kid: KEY_ID, n: jwkPublic.n, e: jwkPublic.e }] });
});

// ─── Authorize ────────────────────────────────────────────────────────────────
app.get("/authorize", (req, res) => {
  const {
    client_id, redirect_uri, response_type, scope, state, nonce,
    code_challenge, code_challenge_method,
    error, reg_error, registered, prefill_username,
  } = req.query;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).send("Unknown client_id");
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid redirect_uri");
  if (response_type !== "code")
    return res.redirect(`${redirect_uri}?error=unsupported_response_type&state=${state || ""}`);

  const hiddenFields = `
    <input type="hidden" name="client_id"             value="${client_id}"/>
    <input type="hidden" name="redirect_uri"          value="${redirect_uri}"/>
    <input type="hidden" name="response_type"         value="code"/>
    <input type="hidden" name="scope"                 value="${scope || "openid profile email"}"/>
    <input type="hidden" name="state"                 value="${state || ""}"/>
    <input type="hidden" name="nonce"                 value="${nonce || ""}"/>
    <input type="hidden" name="code_challenge"        value="${code_challenge || ""}"/>
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}"/>
  `;

  const loginError = error === "invalid_credentials" ? "Invalid username or password." : (error || "");

  const regErrorMap = {
    username_taken:    "That username is already taken.",
    password_mismatch: "Passwords do not match.",
    missing_fields:    "All fields are required.",
    username_invalid:  "Username: 3–32 chars, letters/numbers/_ only.",
  };
  const regError = regErrorMap[reg_error] || reg_error || "";

  res.send(renderPage({ client, loginError, regError, registered: !!registered, hiddenFields, prefillUsername: prefill_username || "" }));
});

// ─── Login submit ─────────────────────────────────────────────────────────────
app.post("/authorize/submit", (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce,
          code_challenge, code_challenge_method, username, password } = req.body;

  const client = CLIENTS[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid request");

  const user = USERS[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    const p = new URLSearchParams({
      client_id, redirect_uri, response_type: response_type || "code",
      scope: scope || "", state: state || "", nonce: nonce || "",
      code_challenge: code_challenge || "", code_challenge_method: code_challenge_method || "",
      error: "invalid_credentials", prefill_username: username || "",
    });
    return res.redirect(`/authorize?${p}`);
  }

  const code = generateCode();
  authCodes.set(code, {
    clientId: client_id, userId: username, redirectUri: redirect_uri,
    nonce, scope: scope || "openid profile email",
    expiresAt: Date.now() + 60_000,
    codeChallenge: code_challenge || null, codeChallengeMethod: code_challenge_method || "S256",
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
});

// ─── Register submit ──────────────────────────────────────────────────────────
app.post("/authorize/register", (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce,
          code_challenge, code_challenge_method,
          name, email, username, password, confirm_password } = req.body;

  const client = CLIENTS[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid request");

  const base = {
    client_id, redirect_uri, response_type: response_type || "code",
    scope: scope || "", state: state || "", nonce: nonce || "",
    code_challenge: code_challenge || "", code_challenge_method: code_challenge_method || "",
  };
  const redir = (reg_error) => res.redirect(`/authorize?${new URLSearchParams({ ...base, reg_error })}`);

  if (!name || !email || !username || !password || !confirm_password) return redir("missing_fields");
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) return redir("username_invalid");
  if (USERS[username]) return redir("username_taken");
  if (password !== confirm_password) return redir("password_mismatch");

  USERS[username] = {
    passwordHash: hashPassword(password),
    name: name.trim(),
    email: email.trim().toLowerCase(),
    createdAt: new Date().toISOString(),
  };
  console.log(`🆕 Registered: ${username} <${email}>`);

  res.redirect(`/authorize?${new URLSearchParams({ ...base, registered: "1" })}`);
});


app.post("/token", (req, res) => {
  let clientId, clientSecret;
  const auth = req.headers.authorization;
  if (auth?.startsWith("Basic ")) {
    [clientId, clientSecret] = Buffer.from(auth.slice(6), "base64").toString().split(":");
  } else {
    clientId = req.body.client_id; clientSecret = req.body.client_secret;
  }

  const client = CLIENTS[clientId];
  if (!client || client.clientSecret !== clientSecret)
    return res.status(401).json({ error: "invalid_client" });

  const { grant_type, code, redirect_uri, code_verifier, refresh_token } = req.body;

  if (grant_type === "authorization_code") {
    const stored = authCodes.get(code);
    if (!stored) return res.status(400).json({ error: "invalid_grant" });
    if (stored.expiresAt < Date.now()) {
      authCodes.delete(code);
      return res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
    }
    if (stored.clientId !== clientId || stored.redirectUri !== redirect_uri)
      return res.status(400).json({ error: "invalid_grant" });
    if (stored.codeChallenge) {
      if (!code_verifier) return res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
      if (!verifyPKCE(code_verifier, stored.codeChallenge, stored.codeChallengeMethod))
        return res.status(400).json({ error: "invalid_grant", error_description: "PKCE failed" });
    }
    authCodes.delete(code);

    const user = USERS[stored.userId];
    const now  = Math.floor(Date.now() / 1000);
    const idToken = signIdToken({ iss: ISSUER, sub: stored.userId, aud: clientId, exp: now + 3600, iat: now, nonce: stored.nonce || undefined, name: user.name, email: user.email });
    const accessToken = signAccessToken({ iss: ISSUER, sub: stored.userId, aud: clientId, scope: stored.scope });
    const rt = generateToken();
    refreshTokens.set(rt, { clientId, userId: stored.userId, scope: stored.scope });

    return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token: idToken, refresh_token: rt, scope: stored.scope });
  }

  if (grant_type === "refresh_token") {
    const stored = refreshTokens.get(refresh_token);
    if (!stored || stored.clientId !== clientId) return res.status(400).json({ error: "invalid_grant" });
    const user = USERS[stored.userId];
    const now  = Math.floor(Date.now() / 1000);
    const idToken = signIdToken({ iss: ISSUER, sub: stored.userId, aud: clientId, exp: now + 3600, iat: now, name: user.name, email: user.email });
    const accessToken = signAccessToken({ iss: ISSUER, sub: stored.userId, aud: clientId, scope: stored.scope });
    return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token: idToken, scope: stored.scope });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});


app.get("/userinfo", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "unauthorized" });
  try {
    const payload = verifyAccessToken(auth.slice(7));
    const user = USERS[payload.sub];
    if (!user) return res.status(404).json({ error: "user_not_found" });
    res.json({ sub: payload.sub, name: user.name, email: user.email });
  } catch { res.status(401).json({ error: "invalid_token" }); }
});


app.get("/logout", (req, res) => {
  const { post_logout_redirect_uri, state } = req.query;
  if (post_logout_redirect_uri) {
    const url = new URL(post_logout_redirect_uri);
    if (state) url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }
  res.send("Logged out.");
});


app.listen(PORT, () => {
  console.log(`🔐 OIDC Provider → ${ISSUER}`);
  console.log(`   Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`   Clients: location-app (3000), checkbox-app (3001)`);
  console.log(`   Seeded users: adarsh (pass123), demo (demo123)`);
});
