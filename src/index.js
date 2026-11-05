import { jwtVerify, createRemoteJWKSet } from "jose";

// Personal, single-account Gmail client. Every route, including assets,
// requires a valid Cloudflare Access JWT before it is served.
const BASE = "https://mail.opel.org.uk";
const REDIRECT_URI = `${BASE}/auth/callback`;
const SCOPE = "https://www.googleapis.com/auth/gmail.modify";
const GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me";
const enc = new TextEncoder();
const keys = new Map();
let cachedAccess = null;

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function fail(message, status = 400) { return json({ error: message }, status); }
function redirect(url, cookies = []) {
  const headers = new Headers({ Location: url, "Cache-Control": "no-store" });
  cookies.forEach(c => headers.append("Set-Cookie", c));
  return new Response(null, { status: 302, headers });
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64url(bytes);
}
function b64url(bytes) {
  let raw = "";
  for (let i = 0; i < bytes.length; i += 32768) {
    raw += String.fromCharCode(...bytes.slice(i, i + 32768));
  }
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function readCookie(request, key) {
  const match = request.headers.get("Cookie")?.match(new RegExp(`(?:^|;\\s*)${key}=([^;]*)`));
  return match?.[1] || "";
}
const cookie = (key, value, maxAge = 600) => `${key}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const clearCookie = key => cookie(key, "", 0);

async function authorize(request, env) {
  if (!env.TEAM_DOMAIN || !env.POLICY_AUD || !env.ALLOWED_ACCESS_EMAIL) return false;
  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!jwt) return false;
  const issuer = env.TEAM_DOMAIN.replace(/\/$/, "");
  if (!/^https:\/\/[a-z0-9.-]+\.cloudflareaccess\.com$/i.test(issuer)) return false;
  try {
    if (!keys.has(issuer)) {
      keys.set(issuer, createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)));
    }
    const { payload } = await jwtVerify(jwt, keys.get(issuer), {
      issuer,
      audience: env.POLICY_AUD,
      algorithms: ["RS256"]
    });
    return String(payload.email || "").toLowerCase() === env.ALLOWED_ACCESS_EMAIL.toLowerCase();
  } catch { return false; }
}

function requireOrigin(request) {
  return request.headers.get("Origin") === BASE &&
    request.headers.get("Content-Type")?.startsWith("application/json");
}

async function encryptToken(token, secret) {
  const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(secret), c => c.charCodeAt(0)), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(token));
  return JSON.stringify({ iv: b64url(iv), data: b64url(new Uint8Array(ciphertext)) });
}
function decode64url(s) {
  const fixed = s.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(fixed + "=".repeat((4 - fixed.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function decryptToken(blob, secret) {
  const { iv, data } = JSON.parse(blob);
  const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(secret), c => c.charCodeAt(0)), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode64url(iv) }, key, decode64url(data));
  return new TextDecoder().decode(plaintext);
}
async function exchange(body, env) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, ...body })
  });
  const tokens = await response.json();
  if (!response.ok) throw new Error("Google could not authorise this request. Try connecting again.");
  return tokens;
}
async function getToken(env) {
  if (cachedAccess && cachedAccess.exp > Date.now() + 60000) return cachedAccess.token;
  const saved = await env.MAIL_TOKENS.get("gmail_refresh_token");
  if (!saved) throw new Error("CONNECT_REQUIRED");
  const refresh_token = await decryptToken(saved, env.TOKEN_ENCRYPTION_KEY);
  const tokens = await exchange({ refresh_token, grant_type: "refresh_token" }, env);
  cachedAccess = { token: tokens.access_token, exp: Date.now() + (tokens.expires_in || 3600) * 1000 };
  return cachedAccess.token;
}
async function googleRequest(env, path, options = {}, tokenOverride) {
  const accessToken = tokenOverride || await getToken(env);
  const response = await fetch(`${GMAIL}${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${accessToken}`, ...(options.body ? { "Content-Type": "application/json" } : {}) }
  });
  if (!response.ok) {
    if (response.status === 401) { cachedAccess = null; throw new Error("Google access expired. Reconnect your account."); }
    throw new Error(`Gmail request failed (${response.status})`);
  }
  return response.json();
}
function head(message, key) {
  return message.payload?.headers?.find(h => h.name.toLowerCase() === key.toLowerCase())?.value || "";
}
function brief(m) {
  return {
    id: m.id,
    from: head(m, "From"), to: head(m, "To"),
    subject: head(m, "Subject") || "(no subject)",
    date: m.internalDate,
    snippet: m.snippet || "",
    unread: (m.labelIds || []).includes("UNREAD"),
    starred: (m.labelIds || []).includes("STARRED")
  };
}
function textBody(payload) {
  if (!payload) return "";
  if (payload.mimeType === "text/plain" && payload.body?.data) {
    return new TextDecoder("utf-8").decode(decode64url(payload.body.data));
  }
  for (const part of payload.parts || []) {
    const found = textBody(part);
    if (found) return found;
  }
  return "";
}
function safeId(s) { return /^[a-zA-Z0-9_-]{5,128}$/.test(s); }
function messagePath(id) { return `/messages/${encodeURIComponent(id)}`; }

async function oauthStart(env) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.ALLOWED_GMAIL || !env.TOKEN_ENCRYPTION_KEY) {
    return fail("Configure Google OAuth secrets first.", 503);
  }
  const state = randomToken();
  const verifier = randomToken();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(verifier));
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID, redirect_uri: REDIRECT_URI,
    response_type: "code", scope: SCOPE, access_type: "offline", prompt: "consent",
    state, code_challenge: b64url(new Uint8Array(digest)), code_challenge_method: "S256",
    login_hint: env.ALLOWED_GMAIL
  });
  return redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, [
    cookie("mail_oauth_state", state), cookie("mail_oauth_verifier", verifier)
  ]);
}
async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const expected = readCookie(request, "mail_oauth_state");
  const verifier = readCookie(request, "mail_oauth_verifier");
  if (!expected || !verifier || url.searchParams.get("state") !== expected || !url.searchParams.get("code")) {
    return fail("OAuth verification failed. Please try connecting again.", 400);
  }
  try {
    const tokens = await exchange({
      code: url.searchParams.get("code"), code_verifier: verifier,
      redirect_uri: REDIRECT_URI, grant_type: "authorization_code"
    }, env);
    const profile = await googleRequest(env, "/profile", {}, tokens.access_token);
    if (profile.emailAddress?.toLowerCase() !== env.ALLOWED_GMAIL.toLowerCase()) {
      return fail("You selected a different Google account than the one configured.", 403);
    }
    if (!tokens.refresh_token) return fail("Google did not return a refresh token. Reconnect and grant consent again.");
    const encrypted = await encryptToken(tokens.refresh_token, env.TOKEN_ENCRYPTION_KEY);
    await env.MAIL_TOKENS.put("gmail_refresh_token", encrypted);
    cachedAccess = { token: tokens.access_token, exp: Date.now() + (tokens.expires_in || 3600) * 1000 };
    return redirect(BASE, [clearCookie("mail_oauth_state"), clearCookie("mail_oauth_verifier")]);
  } catch {
    return fail("Google connection failed. Check your OAuth settings and try again.", 502);
  }
}

async function listMessages(url, env) {
  const folder = url.searchParams.get("folder") || "INBOX";
  const valid = new Set(["INBOX", "SENT", "STARRED", "TRASH", "ALL"]);
  if (!valid.has(folder)) return fail("Unknown folder");
  const q = (url.searchParams.get("q") || "").slice(0, 160);
  const p = new URLSearchParams({ maxResults: "25" });
  if (folder !== "ALL") p.set("labelIds", folder);
  if (q) p.set("q", q);
  if (folder === "TRASH") p.set("includeSpamTrash", "true");
  const page = url.searchParams.get("page");
  if (page && page.length <= 2048) p.set("pageToken", page);
  const list = await googleRequest(env, `/messages?${p}`);
  const items = list.messages || [];
  // Limit concurrent reads; do not log message contents.
  const messages = [];
  for (let i = 0; i < items.length; i += 5) {
    const chunk = await Promise.all(items.slice(i, i + 5).map(m => googleRequest(env, `${messagePath(m.id)}?format=full`)));
    messages.push(...chunk.map(brief));
  }
  return json({ messages, nextPageToken: list.nextPageToken || null });
}

async function openMessage(id, env) {
  if (!safeId(id)) return fail("Invalid message ID");
  const m = await googleRequest(env, `${messagePath(id)}?format=full`);
  return json({ ...brief(m), body: textBody(m.payload) || "This message contains HTML-only or attachment content that is not shown in this text preview." });
}
async function changeMessage(request, id, env) {
  if (!safeId(id) || !requireOrigin(request)) return fail("Invalid request", 403);
  const { action } = await request.json();
  if (action === "trash") {
    await googleRequest(env, `${messagePath(id)}/trash`, { method: "POST", body: "{}" });
  } else {
    const actions = {
      read: { removeLabelIds: ["UNREAD"] },
      unread: { addLabelIds: ["UNREAD"] },
      star: { addLabelIds: ["STARRED"] },
      unstar: { removeLabelIds: ["STARRED"] },
      archive: { removeLabelIds: ["INBOX"] }
    };
    if (!Object.hasOwn(actions, action)) return fail("Unknown action");
    await googleRequest(env, `${messagePath(id)}/modify`, { method: "POST", body: JSON.stringify(actions[action]) });
  }
  return json({ ok: true });
}
function encodeMessage(str) { return b64url(enc.encode(str)); }
function mimeBase64(str) {
  const value = encodeMessage(str).replace(/-/g, "+").replace(/_/g, "/");
  const padded = value + "=".repeat((4 - value.length % 4) % 4);
  return padded.match(/.{1,76}/g)?.join("\r\n") || "";
}
async function sendMessage(request, env) {
  if (!requireOrigin(request)) return fail("Invalid origin", 403);
  const { to, subject, body } = await request.json();
  const recipient = String(to || "").trim();
  const subjectText = String(subject || "").trim();
  const message = String(body || "");
  if (recipient.length > 1000 || !recipient || !recipient.split(",").every(e => /^[^\s@,<>]+@[^\s@,<>]+\.[^\s@,<>]+$/.test(e.trim())) ||
      /[\r\n]/.test(recipient) || /[\r\n]/.test(subjectText) || subjectText.length > 500 || message.length > 100000) {
    return fail("Check recipient, subject and message length.");
  }
  const raw = [
    `From: ${env.ALLOWED_GMAIL}`,
    `To: ${recipient}`,
    `Subject: =?UTF-8?B?${mimeBase64(subjectText).replace(/\r\n/g, "")}?=`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    mimeBase64(message)
  ].join("\r\n");
  await googleRequest(env, "/messages/send", { method: "POST", body: JSON.stringify({ raw: encodeMessage(raw) }) });
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    try {
      if (!await authorize(request, env)) return fail("Access denied. Check Cloudflare Access configuration.", 403);
      const url = new URL(request.url);
      if (url.origin !== BASE) return fail("Use the protected mail.opel.org.uk hostname.", 403);
      if (url.pathname === "/auth/google" && request.method === "GET") return oauthStart(env);
      if (url.pathname === "/auth/callback" && request.method === "GET") return oauthCallback(request, env);
      if (url.pathname === "/api/status" && request.method === "GET") {
        return json({ connected: Boolean(await env.MAIL_TOKENS.get("gmail_refresh_token")), email: env.ALLOWED_GMAIL || "" });
      }
      if (url.pathname === "/api/messages" && request.method === "GET") return listMessages(url, env);
      const match = url.pathname.match(/^\/api\/messages\/([a-zA-Z0-9_-]+)(?:\/action)?$/);
      if (match && request.method === "GET" && !url.pathname.endsWith("/action")) return openMessage(match[1], env);
      if (match && request.method === "POST" && url.pathname.endsWith("/action")) return changeMessage(request, match[1], env);
      if (url.pathname === "/api/send" && request.method === "POST") return sendMessage(request, env);
      if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/")) return fail("Not found", 404);
      const asset = await env.ASSETS.fetch(request);
      const headers = new Headers(asset.headers);
      headers.set("Cache-Control", "no-store");
      headers.set("X-Content-Type-Options", "nosniff");
      headers.set("Referrer-Policy", "no-referrer");
      headers.set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
      return new Response(asset.body, { status: asset.status, headers });
    } catch (err) {
      if (err.message === "CONNECT_REQUIRED") return fail("Connect Gmail first.", 401);
      return fail(err instanceof Error ? err.message : "Service unavailable", 502);
    }
  }
};
