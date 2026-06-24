import http from "node:http";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const host = process.env.REPOINTEL_DEBUG_UI_HOST || "0.0.0.0";
const port = Number(process.env.PORT || process.env.REPOINTEL_DEBUG_UI_PORT || "18110");
const repointelBase = stripSlash(process.env.REPOINTEL_BASE_URL || "http://127.0.0.1:18101");
const collectionBase = stripSlash(
  process.env.METADATA_COLLECTION_BASE_URL || "http://127.0.0.1:18102",
);
const repointelDatabaseUrl = process.env.REPOINTEL_DATABASE_URL || "";
const analyticsProviderToken = firstEnv([
  "REPOINTEL_ANALYTICS_PROVIDER_TOKEN",
  "METADATACOLLECTIONFACADE_REPOINTEL_ANALYTICS_PROVIDER_TOKEN",
  "FRONTPLANE_AUTH_REPOINTEL_ANALYTICS_PROVIDER_TOKEN",
]);
const analyticsProviderMode = process.argv[2] === "--analytics-provider";
const configuredSessionSecret = firstEnv(["REPO_INTEL_SESSION_SECRET", "METADATA_COLLECTION_SESSION_SECRET"]);
const sessionSecret = configuredSessionSecret || crypto.randomBytes(32).toString("hex");
const sessionCookieName = process.env.REPO_INTEL_SESSION_COOKIE || "repo_intel_session";
const sessionTtlSeconds = parsePositiveInt(process.env.REPO_INTEL_SESSION_TTL_SECONDS, 8 * 60 * 60);
const sessionSameSite = ["Strict", "Lax", "None"].includes(process.env.REPO_INTEL_COOKIE_SAMESITE || "")
  ? process.env.REPO_INTEL_COOKIE_SAMESITE
  : "Lax";
const sessionCookieSecureMode = String(process.env.REPO_INTEL_COOKIE_SECURE || "auto").trim().toLowerCase();
const bootstrapAdminUsername = firstEnv([
  "REPO_INTEL_BOOTSTRAP_ADMIN_USERNAME",
  "REPOINTEL_BOOTSTRAP_ADMIN_USERNAME",
]) || "admin";
const bootstrapAdminPassword = String(process.env.REPO_INTEL_BOOTSTRAP_ADMIN_PASSWORD || "");
const bootstrapAdminPasswordHash = firstEnv([
  "REPO_INTEL_BOOTSTRAP_ADMIN_PASSWORD_HASH",
  "REPOINTEL_BOOTSTRAP_ADMIN_PASSWORD_HASH",
]);
const localLoginEnabled = Boolean(bootstrapAdminPassword || bootstrapAdminPasswordHash);
const oidcConfig = {
  issuer: stripSlash(firstEnv(["REPO_INTEL_OIDC_ISSUER_URL", "OIDC_ISSUER_URL"])),
  clientId: firstEnv(["REPO_INTEL_OIDC_CLIENT_ID", "OIDC_CLIENT_ID"]),
  clientSecret: firstEnv(["REPO_INTEL_OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET"]),
  redirectUri: firstEnv(["REPO_INTEL_OIDC_REDIRECT_URI", "OIDC_REDIRECT_URI"]),
  scope: firstEnv(["REPO_INTEL_OIDC_SCOPE", "OIDC_SCOPE"]) || "openid profile email",
  rolesClaim: firstEnv(["REPO_INTEL_OIDC_ROLES_CLAIM", "OIDC_ROLES_CLAIM"]) || "roles",
  defaultRole: normalizeProductRole(firstEnv(["REPO_INTEL_OIDC_DEFAULT_ROLE", "OIDC_DEFAULT_ROLE"]) || "read_only_viewer"),
};
const oidcEnabled = Boolean(oidcConfig.issuer && oidcConfig.clientId && oidcConfig.redirectUri);
const sessions = new Map();
const oidcLoginStates = new Map();
let oidcDiscoveryCache = null;
let oidcJwksCache = null;
const keywordScoreCap = 160;
const reviewRiskCaps = {
  security: 320,
  author: 220,
  reviewer: 100,
  implementation: 200,
  friction: 80,
  rework: 50,
  stale: 30,
};

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

if (analyticsProviderMode) {
  if (!analyticsProviderToken) {
    console.error("Set REPOINTEL_ANALYTICS_PROVIDER_TOKEN or METADATACOLLECTIONFACADE_REPOINTEL_ANALYTICS_PROVIDER_TOKEN to start the analytics provider.");
    process.exitCode = 2;
  } else {
    startAnalyticsProvider();
  }
} else {
  startGateway();
}

function startGateway() {
  if (!configuredSessionSecret) {
    console.warn("REPO_INTEL_SESSION_SECRET is not set; using an ephemeral in-memory session secret for this process.");
  }
  if (!localLoginEnabled && !oidcEnabled) {
    console.warn("No login provider is configured. Set OIDC env vars or REPO_INTEL_BOOTSTRAP_ADMIN_PASSWORD.");
  }
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", "http://localhost");
      if (url.pathname === "/healthz") {
        return json(res, {
          status: "ok",
          service: "repo-intel-gateway",
          auth: "session-cookie",
          oidcEnabled,
          localLoginEnabled,
        });
      }
      if (url.pathname.startsWith("/auth/")) {
        return handleAuth(req, res, url);
      }
      if (url.pathname === "/login" || url.pathname === "/login.html") {
        return serveStatic(req, res, "login.html");
      }
      if (url.pathname === "/styles.css") {
        return serveStatic(req, res);
      }
      if (url.pathname === "/api/config") {
        const session = requireAuthenticated(req, res);
        if (!session) return;
        const policy = authorizeApiRequest(req, res, "metadata", "/console/config", session);
        if (!policy) return;
        return proxy(req, res, collectionBase, "/metadata-collection/console/config", {
          service: "metadata",
          scope: policy.downstreamScope,
          user: session.user,
        });
      }
      if (url.pathname.startsWith("/api/repointel/") || url.pathname === "/api/repointel") {
        const session = requireAuthenticated(req, res);
        if (!session) return;
        const tailPath = url.pathname.replace(/^\/api\/repointel/, "") || "/";
        const policy = authorizeApiRequest(req, res, "repointel", tailPath, session);
        if (!policy) return;
        return proxy(req, res, repointelBase, `${tailPath}${url.search}`, {
          service: "repointel",
          scope: policy.downstreamScope,
          user: session.user,
        });
      }
      if (url.pathname.startsWith("/api/metadata/") || url.pathname === "/api/metadata") {
        const session = requireAuthenticated(req, res);
        if (!session) return;
        const tailPath = url.pathname.replace(/^\/api\/metadata/, "") || "/";
        const policy = authorizeApiRequest(req, res, "metadata", tailPath, session);
        if (!policy) return;
        if (tailPath === "/healthz" || tailPath === "/metrics") {
          return proxy(req, res, collectionBase, `${tailPath}${url.search}`, {
            service: "metadata",
            scope: policy.downstreamScope,
            user: session.user,
          });
        }
        return proxy(req, res, collectionBase, `/metadata-collection${tailPath}${url.search}`, {
          service: "metadata",
          scope: policy.downstreamScope,
          user: session.user,
        });
      }
      const session = requireAuthenticated(req, res, { html: true });
      if (!session) return;
      if ((url.pathname === "/debug" || url.pathname.startsWith("/debug/")) && !userHasAnyProductRole(session.user, ["administrator"])) {
        return htmlForbidden(res);
      }
      return serveStatic(req, res);
    } catch (err) {
      writeJson(res, 500, { error: "GatewayError", message: String(err?.message || err) });
    }
  });

  server.listen(port, host, () => {
    console.log(`Repo Intel gateway listening on http://${host}:${port}`);
    console.log(`Browser API paths stay same-origin and session-authenticated: /api/repointel and /api/metadata`);
    console.log(`Internal RepointelFacade target -> ${repointelBase}`);
    console.log(`Internal MetadataCollectionFacade target -> ${collectionBase}/metadata-collection`);
  });
}

function startAnalyticsProvider() {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method !== "GET") {
        res.writeHead(405, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "MethodNotAllowed", message: "GET required" }));
        return;
      }
      if (!authorizedProviderRequest(req, analyticsProviderToken)) {
        res.writeHead(401, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "Unauthorized", message: "valid analytics provider bearer token required" }));
        return;
      }
      const url = new URL(req.url || "/", "http://localhost");
      const queryName = analyticsProviderQueryName(url.pathname);
      if (!queryName) {
        res.writeHead(404, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "NotFound", message: `No analytics provider route for ${url.pathname}` }));
        return;
      }
      json(res, await runConsoleQuery(queryName, Object.fromEntries(url.searchParams.entries())));
    } catch (err) {
      const status = !repointelDatabaseUrl ? 503 : 500;
      res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "AnalyticsProviderError", message: String(err?.message || err) }));
    }
  });

  server.listen(port, host, () => {
    console.log(`Repointel analytics provider listening on http://${host}:${port}`);
  });
}

function analyticsProviderQueryName(pathname) {
  const routes = {
    "/analytics/repointel-analytics": "repointel-analytics",
    "/analytics/repointel-author-history": "repointel-author-history",
    "/analytics/repointel-ideas-base": "repointel-ideas-base",
    "/analytics/repointel-loci": "repointel-loci",
    "/analytics/repointel-loci-extended": "repointel-loci-extended",
    "/analytics/repointel-review-risk": "repointel-review-risk",
    "/analytics/repointel-review-risk-messages": "repointel-review-risk-messages",
  };
  return routes[pathname] || "";
}

async function runConsoleQuery(queryName, input = {}) {
  if (!repointelDatabaseUrl) {
    throw new Error("Set REPOINTEL_DATABASE_URL to enable Repointel console analytics.");
  }
  switch (queryName) {
    case "repointel-analytics":
      return queryRepointelAnalytics({
        minCommits: parsePositiveInt(input.min_commits ?? input.minCommits, 10),
        minApprovals: parsePositiveInt(input.min_approvals ?? input.minApprovals, 10),
      });
    case "repointel-author-history": {
      const options = {
        q: String(input.q || ""),
        name: String(input.name || ""),
        lastName: String(input.last_name || input.lastName || ""),
        email: String(input.email || ""),
        authorId: String(input.author_id || input.authorId || ""),
        externalAuthorId: String(input.external_author_id || input.externalAuthorId || ""),
        gerritAccountId: String(input.gerrit_account_id || input.gerritAccountId || ""),
        changeNumber: String(input.change_number || input.changeNumber || ""),
        repositoryId: String(input.repository_id || input.repositoryId || ""),
        project: String(input.project || ""),
        includeBugs: parseBooleanParam(input.include_bugs ?? input.includeBugs, true),
        limit: Math.min(500, parsePositiveInt(input.limit, 50)),
        bugLimit: Math.min(200, parsePositiveInt(input.bug_limit ?? input.bugLimit, 50)),
        reviewLimit: Math.min(500, parsePositiveInt(input.review_limit ?? input.reviewLimit, 100)),
        commitLimit: Math.min(500, parsePositiveInt(input.commit_limit ?? input.commitLimit, 100)),
      };
      if (!hasAuthorHistoryIdentity(options)) {
        throw new Error("Provide one of q, name, last_name, email, author_id, external_author_id, gerrit_account_id, or change_number.");
      }
      return queryRepointelAuthorHistory(options);
    }
    case "repointel-ideas-base":
      return queryRepointelIdeasBase({
        minCommits: parsePositiveInt(input.min_commits ?? input.minCommits, 10),
        minApprovals: parsePositiveInt(input.min_approvals ?? input.minApprovals, 10),
      });
    case "repointel-loci":
      return queryRepointelLociAnalytics();
    case "repointel-loci-extended":
      return queryRepointelLociExtendedAnalytics();
    case "repointel-review-risk":
      return queryRepointelReviewRisk({
        repositoryId: String(input.repository_id || input.repositoryId || ""),
        project: String(input.project || ""),
        status: String(input.status || "NEW"),
        month: String(input.month || ""),
        since: String(input.since || ""),
        until: String(input.until || ""),
        dateField: String(input.date_field || input.dateField || "created"),
        limit: parsePositiveInt(input.limit, 1000),
      });
    case "repointel-review-risk-messages":
      return queryRepointelReviewRiskMessages({
        changeNumber: String(input.change_number || input.changeNumber || ""),
        project: String(input.project || ""),
        repositoryId: String(input.repository_id || input.repositoryId || ""),
        minScore: Number(input.min_score ?? input.minScore ?? 40),
      });
    default:
      throw new Error(`unknown analytics query ${queryName}`);
  }
}

async function serveStatic(req, res, fileOverride = "") {
  const url = new URL(req.url || "/", "http://localhost");
  const safePath = normalize(decodeURIComponent(url.pathname))
    .replace(/^(\.\.[/\\])+/, "")
    .replace(/^[/\\]+/, "");
  const filePath = join(root, fileOverride || safePath || "index.html");
  try {
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": types[extname(filePath)] || "application/octet-stream",
      "cache-control": "no-store",
      ...securityHeaders(),
    });
    res.end(body);
  } catch {
    const body = await readFile(join(root, "index.html"));
    res.writeHead(200, { "content-type": types[".html"], "cache-control": "no-store", ...securityHeaders() });
    res.end(body);
  }
}

async function proxy(req, res, base, path, options = {}) {
  const target = `${base}${path}`;
  const token = downstreamToken(options.service, options.scope);
  if (!token) {
    writeJson(res, 503, {
      error: "GatewayCredentialUnavailable",
      message: `No internal ${options.scope || "reader"} credential is configured for ${options.service || "upstream"}.`,
    });
    return;
  }
  const headers = proxyHeaders(req.headers);
  headers.authorization = `Bearer ${token}`;
  if (options.user?.subject_id) headers["x-repo-intel-user"] = String(options.user.subject_id);
  if (options.user?.roles?.length) headers["x-repo-intel-roles"] = options.user.roles.join(",");
  const body = await readBody(req);
  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body: body.length ? body : undefined,
    });
    const responseBody = Buffer.from(await upstream.arrayBuffer());
    const responseHeaders = {
      "content-type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...securityHeaders(),
    };
    res.writeHead(upstream.status, responseHeaders);
    res.end(responseBody);
  } catch (err) {
    writeJson(res, 502, {
      error: "UpstreamUnavailable",
      message: "Could not reach the upstream service through the gateway.",
      detail: userHasAnyProductRole(options.user, ["administrator"]) ? String(err?.message || err) : undefined,
    });
  }
}

async function handleAuth(req, res, url) {
  if (url.pathname === "/auth/session" && req.method === "GET") {
    const session = currentSession(req);
    return json(res, {
      authenticated: Boolean(session),
      user: session ? publicUser(session.user) : null,
      csrfToken: session?.csrfToken || "",
      debugAllowed: session ? userHasAnyProductRole(session.user, ["administrator"]) : false,
      modes: { local: localLoginEnabled, oidc: oidcEnabled },
    });
  }
  if (url.pathname === "/auth/login/local" && req.method === "POST") {
    return loginLocal(req, res);
  }
  if (url.pathname === "/auth/logout" && (req.method === "POST" || req.method === "GET")) {
    const session = currentSession(req);
    if (session) sessions.delete(session.id);
    return writeJson(res, 200, { ok: true }, { "set-cookie": clearSessionCookie(req) });
  }
  if (url.pathname === "/auth/oidc/login" && req.method === "GET") {
    return beginOidcLogin(req, res);
  }
  if (url.pathname === "/auth/oidc/callback" && req.method === "GET") {
    return completeOidcLogin(req, res, url);
  }
  writeJson(res, 404, { error: "NotFound", message: "Unknown authentication route." });
}

async function loginLocal(req, res) {
  if (!localLoginEnabled) {
    writeJson(res, 404, { error: "LocalLoginDisabled", message: "Bootstrap administrator login is not configured." });
    return;
  }
  const body = await readJsonBody(req);
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!constantTimeEqual(username, bootstrapAdminUsername) || !verifyBootstrapPassword(password)) {
    writeJson(res, 401, { error: "Unauthorized", message: "Invalid username or password." });
    return;
  }
  const session = createSession({
    subject_id: `bootstrap:${username}`,
    handle: username,
    roles: ["administrator"],
    auth_provider: "bootstrap",
  });
  writeJson(res, 200, {
    authenticated: true,
    user: publicUser(session.user),
    csrfToken: session.csrfToken,
    debugAllowed: true,
  }, { "set-cookie": sessionCookie(req, session.id, sessionTtlSeconds) });
}

async function beginOidcLogin(req, res) {
  if (!oidcEnabled) {
    writeJson(res, 404, { error: "OidcDisabled", message: "OIDC login is not configured." });
    return;
  }
  const discovery = await oidcDiscovery();
  const state = randomBase64Url(32);
  const nonce = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  oidcLoginStates.set(state, {
    nonce,
    verifier,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  pruneOidcStates();
  const authUrl = new URL(discovery.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", oidcConfig.clientId);
  authUrl.searchParams.set("redirect_uri", oidcConfig.redirectUri);
  authUrl.searchParams.set("scope", oidcConfig.scope);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("nonce", nonce);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("code_challenge", base64UrlEncode(crypto.createHash("sha256").update(verifier).digest()));
  redirect(res, 302, authUrl.toString());
}

async function completeOidcLogin(req, res, url) {
  if (!oidcEnabled) {
    writeJson(res, 404, { error: "OidcDisabled", message: "OIDC login is not configured." });
    return;
  }
  if (url.searchParams.get("error")) {
    writeJson(res, 401, {
      error: "OidcError",
      message: url.searchParams.get("error_description") || url.searchParams.get("error") || "OIDC login failed.",
    });
    return;
  }
  const state = String(url.searchParams.get("state") || "");
  const stateRecord = oidcLoginStates.get(state);
  oidcLoginStates.delete(state);
  if (!stateRecord || stateRecord.expiresAt <= Date.now()) {
    writeJson(res, 401, { error: "OidcStateInvalid", message: "OIDC state is missing or expired." });
    return;
  }
  const code = String(url.searchParams.get("code") || "");
  if (!code) {
    writeJson(res, 401, { error: "OidcCodeMissing", message: "OIDC callback did not include an authorization code." });
    return;
  }
  const discovery = await oidcDiscovery();
  const tokenResponse = await exchangeOidcCode(discovery, code, stateRecord.verifier);
  const claims = await verifyOidcIdToken(discovery, tokenResponse.id_token, stateRecord.nonce);
  const roles = oidcProductRoles(claims);
  const session = createSession({
    subject_id: String(claims.sub),
    handle: String(claims.preferred_username || claims.email || claims.name || claims.sub),
    roles,
    auth_provider: "oidc",
  });
  redirect(res, 303, "/", { "set-cookie": sessionCookie(req, session.id, sessionTtlSeconds) });
}

function requireAuthenticated(req, res, options = {}) {
  const session = currentSession(req);
  if (session) return session;
  if (options.html) {
    redirect(res, 303, "/login");
  } else {
    writeJson(res, 401, { error: "Unauthorized", message: "Login required." });
  }
  return null;
}

function currentSession(req) {
  const signed = parseCookies(req.headers.cookie || "")[sessionCookieName];
  const id = verifySignedValue(signed);
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = Date.now();
  return session;
}

function createSession(user) {
  const id = randomBase64Url(32);
  const roles = normalizeProductRoles(user.roles);
  const session = {
    id,
    user: {
      subject_id: String(user.subject_id || ""),
      handle: String(user.handle || user.subject_id || ""),
      roles,
      auth_provider: String(user.auth_provider || ""),
    },
    csrfToken: randomBase64Url(32),
    createdAt: Date.now(),
    lastSeenAt: Date.now(),
    expiresAt: Date.now() + sessionTtlSeconds * 1000,
  };
  sessions.set(id, session);
  pruneSessions();
  return session;
}

function publicUser(user) {
  return {
    subject_id: user.subject_id,
    handle: user.handle,
    roles: user.roles,
    roleLabels: user.roles.map(productRoleLabel),
    auth_provider: user.auth_provider,
  };
}

function authorizeApiRequest(req, res, service, path, session) {
  if (!requireCsrf(req, res, session)) return null;
  const policy = apiAccessPolicy(service, req.method, path);
  if (!userHasAnyProductRole(session.user, policy.productRoles)) {
    writeJson(res, 403, {
      error: "Forbidden",
      message: `This action requires ${policy.productRoles.map(productRoleLabel).join(" or ")}.`,
    });
    return null;
  }
  return policy;
}

function requireCsrf(req, res, session) {
  if (safeHttpMethod(req.method)) return true;
  const supplied = String(req.headers["x-csrf-token"] || "");
  if (session?.csrfToken && constantTimeEqual(supplied, session.csrfToken)) return true;
  writeJson(res, 403, { error: "CsrfRejected", message: "Missing or invalid CSRF token." });
  return false;
}

function apiAccessPolicy(service, method, path) {
  const upper = String(method || "GET").toUpperCase();
  const normalizedPath = String(path || "/");
  if (safeHttpMethod(upper) || readLikeAction(upper, normalizedPath)) {
    return { productRoles: ["read_only_viewer"], downstreamScope: "reader" };
  }
  if (upper === "DELETE") {
    return { productRoles: ["administrator"], downstreamScope: "admin" };
  }
  if (service === "repointel") {
    if (startsWithAny(normalizedPath, ["/repository-groups", "/repositories", "/sources", "/ingestion-jobs"])) {
      return { productRoles: ["repository_manager"], downstreamScope: "writer" };
    }
    if (startsWithAny(normalizedPath, ["/normalizers", "/metadata", "/relationships"])) {
      return { productRoles: ["security_analyst"], downstreamScope: "writer" };
    }
    return { productRoles: ["administrator"], downstreamScope: "admin" };
  }
  if (service === "metadata") {
    if (startsWithAny(normalizedPath, ["/runs", "/evidence-hits", "/szz-analyses", "/keyword-configs"])) {
      return { productRoles: ["security_analyst"], downstreamScope: "writer" };
    }
    if (startsWithAny(normalizedPath, ["/coverage-reports", "/scores", "/score-buckets"])) {
      return { productRoles: ["security_analyst"], downstreamScope: "writer" };
    }
    if (startsWithAny(normalizedPath, ["/profiles", "/scenarios", "/dictionaries", "/extractor-bundles", "/extractor-rules", "/downstream-services"])) {
      return { productRoles: ["administrator"], downstreamScope: "admin" };
    }
  }
  return { productRoles: ["administrator"], downstreamScope: "admin" };
}

function readLikeAction(method, path) {
  if (String(method || "").toUpperCase() !== "POST") return false;
  return /:(search|plan|latest|resolve|compute)$/.test(path) || path.includes(":search");
}

function safeHttpMethod(method) {
  return ["GET", "HEAD", "OPTIONS"].includes(String(method || "").toUpperCase());
}

function startsWithAny(value, prefixes) {
  return prefixes.some((prefix) => value === prefix || value.startsWith(`${prefix}/`) || value.startsWith(`${prefix}:`));
}

function userHasAnyProductRole(user, requiredRoles) {
  const roles = new Set(normalizeProductRoles(user?.roles || []));
  if (roles.has("administrator")) return true;
  if (requiredRoles.includes("read_only_viewer")) return roles.size > 0;
  return requiredRoles.some((role) => roles.has(role));
}

function normalizeProductRoles(values) {
  const roles = new Set();
  for (const value of Array.isArray(values) ? values : [values]) {
    const normalized = normalizeProductRole(value);
    if (normalized) roles.add(normalized);
  }
  return Array.from(roles);
}

function normalizeProductRole(value) {
  const role = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  const aliases = {
    admin: "administrator",
    administrator: "administrator",
    repo_admin: "administrator",
    repository_admin: "administrator",
    repository_manager: "repository_manager",
    repo_manager: "repository_manager",
    manager: "repository_manager",
    security_analyst: "security_analyst",
    analyst: "security_analyst",
    writer: "security_analyst",
    read_only_viewer: "read_only_viewer",
    readonly_viewer: "read_only_viewer",
    read_only: "read_only_viewer",
    viewer: "read_only_viewer",
    reader: "read_only_viewer",
    read: "read_only_viewer",
  };
  return aliases[role] || "";
}

function productRoleLabel(role) {
  return {
    administrator: "Administrator",
    repository_manager: "Repository manager",
    security_analyst: "Security analyst",
    read_only_viewer: "Read-only viewer",
  }[role] || role;
}

function downstreamToken(service, scope = "reader") {
  const normalizedScope = ["reader", "writer", "admin"].includes(scope) ? scope : "reader";
  if (service === "metadata") {
    if (normalizedScope === "admin") {
      return firstEnv(["METADATA_COLLECTION_ADMIN_TOKEN", "METADATA_COLLECTION_GATEWAY_ADMIN_TOKEN", "METADATA_COLLECTION_GATEWAY_TOKEN", "METADATA_COLLECTION_TOKEN"]);
    }
    if (normalizedScope === "writer") {
      return firstEnv(["METADATA_COLLECTION_WRITER_TOKEN", "METADATA_COLLECTION_GATEWAY_WRITER_TOKEN", "METADATA_COLLECTION_GATEWAY_TOKEN", "METADATA_COLLECTION_TOKEN"]);
    }
    return firstEnv(["METADATA_COLLECTION_READER_TOKEN", "METADATA_COLLECTION_GATEWAY_READER_TOKEN", "METADATA_COLLECTION_GATEWAY_TOKEN", "METADATA_COLLECTION_TOKEN"]);
  }
  if (service === "repointel") {
    if (normalizedScope === "admin") {
      return firstEnv(["REPOINTEL_ADMIN_TOKEN", "REPOINTEL_GATEWAY_ADMIN_TOKEN", "REPOINTEL_GATEWAY_TOKEN", "METADATA_COLLECTION_REPOINTEL_TOKEN", "REPOINTEL_TOKEN"]);
    }
    if (normalizedScope === "writer") {
      return firstEnv(["REPOINTEL_WRITER_TOKEN", "REPOINTEL_GATEWAY_WRITER_TOKEN", "REPOINTEL_GATEWAY_TOKEN", "METADATA_COLLECTION_REPOINTEL_TOKEN", "REPOINTEL_TOKEN"]);
    }
    return firstEnv(["REPOINTEL_READER_TOKEN", "REPOINTEL_GATEWAY_READER_TOKEN", "REPOINTEL_GATEWAY_TOKEN", "METADATA_COLLECTION_REPOINTEL_TOKEN", "REPOINTEL_TOKEN"]);
  }
  return "";
}

function proxyHeaders(incoming) {
  const headers = { ...incoming };
  for (const key of [
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "authorization",
    "cookie",
    "x-csrf-token",
  ]) {
    delete headers[key];
  }
  return headers;
}

function verifyBootstrapPassword(password) {
  if (bootstrapAdminPasswordHash) {
    const hash = bootstrapAdminPasswordHash.trim();
    if (hash.startsWith("sha256:")) {
      const expected = hash.slice("sha256:".length);
      const actual = crypto.createHash("sha256").update(password).digest("hex");
      return constantTimeEqual(actual, expected);
    }
    if (hash.startsWith("pbkdf2-sha256:")) {
      const [, iterationsRaw, salt, expected] = hash.split(":");
      const iterations = Number(iterationsRaw || 0);
      if (!iterations || !salt || !expected) return false;
      const actual = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex");
      return constantTimeEqual(actual, expected);
    }
    return false;
  }
  return constantTimeEqual(password, bootstrapAdminPassword);
}

async function oidcDiscovery() {
  if (oidcDiscoveryCache && oidcDiscoveryCache.expiresAt > Date.now()) return oidcDiscoveryCache.value;
  const response = await fetch(`${oidcConfig.issuer}/.well-known/openid-configuration`, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new Error(`OIDC discovery failed with HTTP ${response.status}`);
  const value = await response.json();
  for (const key of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (!value[key]) throw new Error(`OIDC discovery is missing ${key}`);
  }
  oidcDiscoveryCache = { value, expiresAt: Date.now() + 10 * 60 * 1000 };
  return value;
}

async function exchangeOidcCode(discovery, code, verifier) {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", oidcConfig.redirectUri);
  body.set("client_id", oidcConfig.clientId);
  body.set("code_verifier", verifier);
  if (oidcConfig.clientSecret) body.set("client_secret", oidcConfig.clientSecret);
  const response = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const value = await response.json().catch(() => ({}));
  if (!response.ok || !value.id_token) {
    throw new Error(value.error_description || value.error || `OIDC token exchange failed with HTTP ${response.status}`);
  }
  return value;
}

async function verifyOidcIdToken(discovery, idToken, expectedNonce) {
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) throw new Error("OIDC id_token is not a JWT.");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(base64UrlDecodeBuffer(encodedHeader).toString("utf8"));
  const claims = JSON.parse(base64UrlDecodeBuffer(encodedPayload).toString("utf8"));
  if (header.alg !== "RS256") {
    throw new Error(`Unsupported OIDC id_token alg ${header.alg || "unknown"}; configure an RS256 provider.`);
  }
  const key = await oidcPublicKey(discovery, header.kid);
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  if (!verifier.verify(key, base64UrlDecodeBuffer(encodedSignature))) {
    throw new Error("OIDC id_token signature verification failed.");
  }
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== discovery.issuer) throw new Error("OIDC id_token issuer mismatch.");
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(oidcConfig.clientId)) throw new Error("OIDC id_token audience mismatch.");
  if (audience.length > 1 && claims.azp && claims.azp !== oidcConfig.clientId) {
    throw new Error("OIDC id_token authorized party mismatch.");
  }
  if (!claims.exp || Number(claims.exp) < now - 60) throw new Error("OIDC id_token is expired.");
  if (claims.nonce !== expectedNonce) throw new Error("OIDC id_token nonce mismatch.");
  if (!claims.sub) throw new Error("OIDC id_token is missing sub.");
  return claims;
}

async function oidcPublicKey(discovery, kid) {
  if (!oidcJwksCache || oidcJwksCache.expiresAt <= Date.now()) {
    const response = await fetch(discovery.jwks_uri, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`OIDC JWKS fetch failed with HTTP ${response.status}`);
    oidcJwksCache = { value: await response.json(), expiresAt: Date.now() + 10 * 60 * 1000 };
  }
  const keys = Array.isArray(oidcJwksCache.value.keys) ? oidcJwksCache.value.keys : [];
  const jwk = keys.find((key) => !kid || key.kid === kid);
  if (!jwk) throw new Error("OIDC JWKS does not contain the id_token signing key.");
  return crypto.createPublicKey({ key: jwk, format: "jwk" });
}

function oidcProductRoles(claims) {
  const rawValues = [
    ...claimValues(claims, oidcConfig.rolesClaim),
    ...claimValues(claims, "groups"),
    ...claimValues(claims, "realm_access.roles"),
  ];
  const mapped = new Set();
  const configuredMappings = {
    administrator: envList("REPO_INTEL_OIDC_ADMIN_ROLES"),
    repository_manager: envList("REPO_INTEL_OIDC_REPOSITORY_MANAGER_ROLES"),
    security_analyst: envList("REPO_INTEL_OIDC_SECURITY_ANALYST_ROLES"),
    read_only_viewer: envList("REPO_INTEL_OIDC_READ_ONLY_VIEWER_ROLES"),
  };
  for (const value of rawValues) {
    const normalized = normalizeProductRole(value);
    if (normalized) mapped.add(normalized);
    for (const [role, configuredValues] of Object.entries(configuredMappings)) {
      if (configuredValues.some((item) => constantTimeEqual(String(value), item))) mapped.add(role);
    }
  }
  if (!mapped.size && oidcConfig.defaultRole) mapped.add(oidcConfig.defaultRole);
  return Array.from(mapped);
}

function claimValues(source, path) {
  const value = String(path || "")
    .split(".")
    .filter(Boolean)
    .reduce((item, key) => (item && typeof item === "object" ? item[key] : undefined), source);
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (typeof value === "string") {
    return value.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean);
  }
  return [];
}

function envList(name) {
  return String(process.env[name] || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

function sessionCookie(req, sessionId, maxAgeSeconds) {
  return cookieHeader(req, sessionCookieName, signValue(sessionId), maxAgeSeconds);
}

function clearSessionCookie(req) {
  return cookieHeader(req, sessionCookieName, "", 0);
}

function cookieHeader(req, name, value, maxAgeSeconds) {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${sessionSameSite}`,
    `Max-Age=${Math.max(0, Number(maxAgeSeconds || 0))}`,
  ];
  if (cookieShouldBeSecure(req)) attrs.push("Secure");
  return attrs.join("; ");
}

function cookieShouldBeSecure(req) {
  if (["1", "true", "yes", "on"].includes(sessionCookieSecureMode)) return true;
  if (["0", "false", "no", "off"].includes(sessionCookieSecureMode)) return false;
  return Boolean(req.socket?.encrypted) || String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

function signValue(value) {
  return `${value}.${hmac(value)}`;
}

function verifySignedValue(value) {
  const text = String(value || "");
  const index = text.lastIndexOf(".");
  if (index <= 0) return "";
  const raw = text.slice(0, index);
  const signature = text.slice(index + 1);
  return constantTimeEqual(hmac(raw), signature) ? raw : "";
}

function hmac(value) {
  return base64UrlEncode(crypto.createHmac("sha256", sessionSecret).update(String(value)).digest());
}

function randomBase64Url(size) {
  return base64UrlEncode(crypto.randomBytes(size));
}

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function base64UrlDecodeBuffer(value) {
  const text = String(value || "").replaceAll("-", "+").replaceAll("_", "/");
  const padded = `${text}${"=".repeat((4 - (text.length % 4)) % 4)}`;
  return Buffer.from(padded, "base64");
}

async function readJsonBody(req) {
  const body = await readBody(req);
  if (!body.length) return {};
  return JSON.parse(body.toString("utf8"));
}

function pruneSessions() {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt <= now) sessions.delete(id);
  }
}

function pruneOidcStates() {
  const now = Date.now();
  for (const [state, value] of oidcLoginStates.entries()) {
    if (value.expiresAt <= now) oidcLoginStates.delete(state);
  }
}

function redirect(res, status, location, headers = {}) {
  res.writeHead(status, {
    location,
    "cache-control": "no-store",
    ...securityHeaders(),
    ...headers,
  });
  res.end();
}

function htmlForbidden(res) {
  res.writeHead(403, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    ...securityHeaders(),
  });
  res.end("<!doctype html><title>Forbidden</title><p>Administrator access required.</p>");
}

function queryRepointelAnalytics(options = {}) {
  const minCommits = Math.max(1, Number(options.minCommits || 10));
  const minApprovals = Math.max(1, Number(options.minApprovals || 10));
  const sql = `
    with
    collection_counts as (
      select collection, count(*)::bigint as count
      from repointel_records
      group by collection
    ),
    sources as (
      select
        id,
        doc->>'name' as name,
        doc->>'provider' as provider,
        doc->>'type' as type,
        doc->>'repository_id' as repository_id
      from repointel_records
      where collection = 'sources'
    ),
    source_counts as (
      select
        s.id,
        s.name,
        s.provider,
        s.type,
        s.repository_id,
        coalesce(raw.count, 0)::bigint as raw_records,
        coalesce(arts.count, 0)::bigint as arts,
        coalesce(metadata.count, 0)::bigint as metadata,
        coalesce(relationships.count, 0)::bigint as relationships,
        coalesce(jobs.count, 0)::bigint as jobs
      from sources s
      left join (
        select doc->>'source_id' as source_id, count(*) as count
        from repointel_records
        where collection = 'raw-records'
        group by 1
      ) raw on raw.source_id = s.id
      left join (
        select doc->>'source_id' as source_id, count(*) as count
        from repointel_records
        where collection = 'arts'
        group by 1
      ) arts on arts.source_id = s.id
      left join (
        select doc->>'source_id' as source_id, count(*) as count
        from repointel_records
        where collection = 'metadata'
        group by 1
      ) metadata on metadata.source_id = s.id
      left join (
        select doc->>'source_id' as source_id, count(*) as count
        from repointel_records
        where collection = 'relationships'
        group by 1
      ) relationships on relationships.source_id = s.id
      left join (
        select doc->>'source_id' as source_id, count(*) as count
        from repointel_records
        where collection = 'ingestion-jobs'
        group by 1
      ) jobs on jobs.source_id = s.id
    ),
    recent_jobs as (
      select jsonb_build_object(
        'id', doc->>'id',
        'status', doc->>'status',
        'requested_by', doc->>'requested_by',
        'mode', doc->>'mode',
        'source_id', doc->>'source_id',
        'raw_records_count', coalesce(nullif(doc->>'raw_records_count', ''), '0')::bigint,
        'arts_count', coalesce(nullif(doc->>'arts_count', ''), '0')::bigint,
        'metadata_count', coalesce(nullif(doc->>'metadata_count', ''), '0')::bigint,
        'relationships_count', coalesce(nullif(doc->>'relationships_count', ''), '0')::bigint,
        'created_at', doc->>'created_at',
        'finished_at', doc->>'finished_at'
      ) as item
      from repointel_records
      where collection = 'ingestion-jobs'
      order by updated_at desc
      limit 20
    ),
    link_samples as (
      select jsonb_build_object(
        'origin', r.doc->>'origin',
        'relation', r.doc->>'relation',
        'from_namespace', mf.doc->>'namespace',
        'from_key', mf.doc->>'key',
        'from_value', left(mf.doc->>'value', 160),
        'to_namespace', mt.doc->>'namespace',
        'to_key', mt.doc->>'key',
        'to_value', left(mt.doc->>'value', 160)
      ) as item
      from repointel_records r
      join repointel_records mf on mf.collection = 'metadata' and mf.id = r.doc->>'from_id'
      join repointel_records mt on mt.collection = 'metadata' and mt.id = r.doc->>'to_id'
      where r.collection = 'relationships'
        and r.doc->>'origin' like 'normalizer.metadata_link.%'
      order by r.updated_at desc
      limit 25
    )
    select jsonb_build_object(
      'generated_at', now(),
      'collection_counts', coalesce((
        select jsonb_agg(jsonb_build_object('collection', collection, 'count', count) order by collection)
        from collection_counts
      ), '[]'::jsonb),
      'source_counts', coalesce((
        select jsonb_agg(to_jsonb(source_counts) order by provider, name)
        from source_counts
      ), '[]'::jsonb),
      'job_status_counts', coalesce((
        select jsonb_agg(jsonb_build_object('status', status, 'count', count) order by status)
        from (
          select doc->>'status' as status, count(*)::bigint as count
          from repointel_records
          where collection = 'ingestion-jobs'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'recent_jobs', coalesce((select jsonb_agg(item) from recent_jobs), '[]'::jsonb),
      'raw_by_type', coalesce((
        select jsonb_agg(jsonb_build_object('type', type, 'count', count) order by count desc)
        from (
          select doc->>'record_type' as type, count(*)::bigint as count
          from repointel_records
          where collection = 'raw-records'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'art_by_type', coalesce((
        select jsonb_agg(jsonb_build_object('type', type, 'count', count) order by count desc)
        from (
          select doc->>'type' as type, count(*)::bigint as count
          from repointel_records
          where collection = 'arts'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'automation_counts', coalesce((
        select jsonb_agg(jsonb_build_object('automated', automated, 'count', count) order by automated)
        from (
          select coalesce(doc->>'automated', 'false') as automated, count(*)::bigint as count
          from repointel_records
          where collection = 'arts' and doc->>'type' = 'code_review_message'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'metadata_by_namespace_key', coalesce((
        select jsonb_agg(jsonb_build_object('namespace', namespace, 'key', key, 'count', count) order by count desc)
        from (
          select doc->>'namespace' as namespace, doc->>'key' as key, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata'
          group by 1, 2
          order by count desc
          limit 80
        ) rows
      ), '[]'::jsonb),
      'relationship_by_origin', coalesce((
        select jsonb_agg(jsonb_build_object('origin', origin, 'count', count) order by count desc)
        from (
          select coalesce(nullif(doc->>'origin', ''), '(none)') as origin, count(*)::bigint as count
          from repointel_records
          where collection = 'relationships'
          group by 1
          order by count desc
          limit 60
        ) rows
      ), '[]'::jsonb),
      'relationship_by_relation', coalesce((
        select jsonb_agg(jsonb_build_object('relation', relation, 'from_type', from_type, 'to_type', to_type, 'count', count) order by count desc)
        from (
          select doc->>'relation' as relation, doc->>'from_type' as from_type, doc->>'to_type' as to_type, count(*)::bigint as count
          from repointel_records
          where collection = 'relationships'
          group by 1, 2, 3
          order by count desc
          limit 60
        ) rows
      ), '[]'::jsonb),
      'security_signals', coalesce((
        select jsonb_agg(jsonb_build_object('key', key, 'count', count) order by count desc)
        from (
          select doc->>'key' as key, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata' and doc->>'namespace' = 'security.signal'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'idea_signal_counts', coalesce((
        select jsonb_agg(jsonb_build_object('signal', signal, 'count', count) order by signal)
        from (
          select 'authors' as signal, count(*)::bigint as count
          from repointel_records where collection = 'authors'
          union all
          select 'arts', count(*)::bigint
          from repointel_records where collection = 'arts'
          union all
          select 'bug_nodes', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'issue.launchpad' and doc->>'key' = 'bug_id'
          union all
          select 'bug_lifecycle', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'issue.launchpad' and doc->>'key' in ('date_created', 'date_last_updated', 'date_last_message', 'message_count', 'security_related', 'duplicate_count', 'information_type')
          union all
          select 'commit_shas', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'git.commit' and doc->>'key' = 'sha'
          union all
          select 'review_votes', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'review.approval' and doc->>'key' in ('vote', 'submit_record_label')
          union all
          select 'review_author_links', count(*)::bigint
          from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_author_link.v1'
          union all
          select 'commit_bug_links', count(*)::bigint
          from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.commit_bug'
          union all
          select 'change_commit_links', count(*)::bigint
          from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_commit'
          union all
          select 'change_file_links', count(*)::bigint
          from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_file'
          union all
          select 'change_component_links', count(*)::bigint
          from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_component'
          union all
          select 'security_signals', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'security.signal'
          union all
          select 'cve_ids', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'security.identifier' and doc->>'key' = 'cve'
          union all
          select 'file_paths', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.file' and doc->>'key' = 'path'
          union all
          select 'components', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.component' and doc->>'key' = 'name'
          union all
          select 'churn', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'git.commit' and doc->>'key' in ('insertions', 'deletions', 'changed_file_count')
          union all
          select 'branches', count(*)::bigint
          from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code_review.gerrit' and doc->>'key' = 'branch'
          union all
          select 'ci_messages', count(*)::bigint
          from repointel_records where collection = 'arts' and doc->>'type' = 'code_review_message' and doc->>'automated' = 'true'
          union all
          select 'dependency_paths', count(*)::bigint
          from repointel_records
          where collection = 'metadata'
            and doc->>'namespace' = 'code.file'
            and doc->>'key' = 'path'
            and (
              doc->>'value' ilike '%requirements%'
              or doc->>'value' ilike '%package.json%'
              or doc->>'value' ilike '%setup.py%'
              or doc->>'value' ilike '%setup.cfg%'
              or doc->>'value' ilike '%pyproject.toml%'
              or doc->>'value' ilike '%tox.ini%'
            )
          union all
          select 'workflow_paths', count(*)::bigint
          from repointel_records
          where collection = 'metadata'
            and doc->>'namespace' = 'code.file'
            and doc->>'key' = 'path'
            and (
              doc->>'value' ilike '%.github/workflows%'
              or doc->>'value' ilike '%zuul%'
              or doc->>'value' ilike '%jenkins%'
            )
          union all
          select 'repo_settings', 0::bigint
          union all
          select 'release_boundaries', 0::bigint
        ) rows
      ), '[]'::jsonb),
      'author_defect_density', coalesce((
        with
        commit_arts as (
          select
            a.id as art_id,
            a.doc->>'author_id' as author_id,
            a.doc->>'raw_record_id' as raw_record_id
          from repointel_records a
          where a.collection = 'arts'
            and a.doc->>'type' = 'commit_message'
            and coalesce(a.doc->>'author_id', '') <> ''
        ),
        author_commits as (
          select author_id, count(distinct art_id)::bigint as commit_count
          from commit_arts
          group by 1
        ),
        commit_line_metadata as (
          select
            m.doc->>'subject_id' as raw_record_id,
            max(case
              when m.doc->>'key' = 'insertions' and m.doc->>'value' ~ '^[0-9]+$'
              then (m.doc->>'value')::bigint
              else 0
            end) as insertions,
            max(case
              when m.doc->>'key' = 'deletions' and m.doc->>'value' ~ '^[0-9]+$'
              then (m.doc->>'value')::bigint
              else 0
            end) as deletions
          from repointel_records m
          where m.collection = 'metadata'
           and m.doc->>'subject_type' = 'raw_record'
           and m.doc->>'namespace' = 'git.commit'
           and m.doc->>'key' in ('insertions', 'deletions')
          group by 1
        ),
        author_lines as (
          select
            ca.author_id,
            sum(coalesce(clm.insertions, 0) + coalesce(clm.deletions, 0))::bigint as changed_lines
          from commit_arts ca
          left join commit_line_metadata clm on clm.raw_record_id = ca.raw_record_id
          group by ca.author_id
        ),
        bug_linked_commits as (
          select ca.author_id, count(distinct ca.art_id)::bigint as bug_linked_commits
          from commit_arts ca
          join repointel_records m
            on m.collection = 'metadata'
           and m.doc->>'subject_type' = 'art'
           and m.doc->>'subject_id' = ca.art_id
           and m.doc->>'namespace' = 'git.commit'
           and m.doc->>'key' = 'sha'
          join repointel_records r
            on r.collection = 'relationships'
           and r.doc->>'origin' = 'normalizer.metadata_link.commit_bug'
           and r.doc->>'from_id' = m.id
          group by 1
        ),
        security_signal_commits as (
          select ca.author_id, count(distinct ca.art_id)::bigint as security_signal_commits
          from commit_arts ca
          join repointel_records m
            on m.collection = 'metadata'
           and m.doc->>'subject_type' = 'art'
           and m.doc->>'subject_id' = ca.art_id
           and m.doc->>'namespace' = 'security.signal'
          group by 1
        ),
        author_rows as (
          select
            ac.author_id,
            coalesce(a.doc->>'display_name', a.doc->>'username', a.doc->>'email', ac.author_id) as author,
            ac.commit_count,
            coalesce(al.changed_lines, 0)::bigint as changed_lines,
            round(coalesce(al.changed_lines, 0)::numeric / 1000, 2) as changed_kloc,
            coalesce(blc.bug_linked_commits, 0)::bigint as bug_linked_commits,
            coalesce(ssc.security_signal_commits, 0)::bigint as security_signal_commits,
            round((coalesce(blc.bug_linked_commits, 0)::numeric / nullif(ac.commit_count, 0)) * 1000, 2) as bug_links_per_1000_commits,
            round((coalesce(ssc.security_signal_commits, 0)::numeric / nullif(ac.commit_count, 0)) * 1000, 2) as security_signals_per_1000_commits,
            round((coalesce(blc.bug_linked_commits, 0)::numeric / nullif(al.changed_lines, 0)) * 1000, 2) as bug_links_per_1000_changed_lines,
            round((coalesce(ssc.security_signal_commits, 0)::numeric / nullif(al.changed_lines, 0)) * 1000, 2) as security_signals_per_1000_changed_lines
          from author_commits ac
          left join author_lines al on al.author_id = ac.author_id
          left join bug_linked_commits blc on blc.author_id = ac.author_id
          left join security_signal_commits ssc on ssc.author_id = ac.author_id
          left join repointel_records a on a.collection = 'authors' and a.id = ac.author_id
          where ac.commit_count >= ${minCommits}
        )
        select jsonb_agg(to_jsonb(author_rows) order by bug_links_per_1000_commits desc, commit_count desc)
        from (
          select *
          from author_rows
          order by bug_links_per_1000_commits desc nulls last, commit_count desc
          limit 50
        ) author_rows
      ), '[]'::jsonb),
      'reviewer_defect_escape_density', coalesce((
        with
        positive_approvals as (
          select
            m.id as approval_meta_id,
            r_author.doc->>'to_id' as reviewer_author_id,
            r_change.doc->>'to_id' as change_meta_id
          from repointel_records m
          join repointel_records r_author
            on r_author.collection = 'relationships'
           and r_author.doc->>'origin' = 'normalizer.metadata_author_link.v1'
           and r_author.doc->>'from_id' = m.id
          join repointel_records r_change
            on r_change.collection = 'relationships'
           and r_change.doc->>'origin' = 'normalizer.metadata_link.approval_change'
           and r_change.doc->>'from_id' = m.id
          where m.collection = 'metadata'
            and m.doc->>'namespace' = 'review.approval'
            and m.doc->>'key' = 'vote'
            and m.doc->'value'->>'action' = 'vote'
            and coalesce((m.doc->'value'->>'value')::int, 0) > 0
        ),
        bug_linked_change_reviews as (
          select distinct
            a.reviewer_author_id,
            a.approval_meta_id,
            a.change_meta_id
          from positive_approvals a
          join repointel_records r_commit
            on r_commit.collection = 'relationships'
           and r_commit.doc->>'origin' = 'normalizer.metadata_link.gerrit_change_commit'
           and r_commit.doc->>'from_id' = a.change_meta_id
          join repointel_records r_bug
            on r_bug.collection = 'relationships'
           and r_bug.doc->>'origin' = 'normalizer.metadata_link.commit_bug'
           and r_bug.doc->>'from_id' = r_commit.doc->>'to_id'
        ),
        reviewer_rows as (
          select
            a.reviewer_author_id,
            coalesce(author_rec.doc->>'display_name', author_rec.doc->>'username', author_rec.doc->>'email', a.reviewer_author_id) as reviewer,
            count(distinct a.approval_meta_id)::bigint as approval_count,
            count(distinct a.change_meta_id)::bigint as approved_change_count,
            count(distinct b.approval_meta_id)::bigint as escaped_approval_count,
            count(distinct b.change_meta_id)::bigint as escaped_change_count,
            round((count(distinct b.approval_meta_id)::numeric / nullif(count(distinct a.approval_meta_id), 0)) * 1000, 2) as escapes_per_1000_approvals,
            round((count(distinct b.change_meta_id)::numeric / nullif(count(distinct a.change_meta_id), 0)) * 1000, 2) as escapes_per_1000_changes
          from positive_approvals a
          left join bug_linked_change_reviews b
            on b.reviewer_author_id = a.reviewer_author_id
           and b.approval_meta_id = a.approval_meta_id
           and b.change_meta_id = a.change_meta_id
          left join repointel_records author_rec
            on author_rec.collection = 'authors'
           and author_rec.id = a.reviewer_author_id
          group by 1, 2
          having count(distinct a.approval_meta_id) >= ${minApprovals}
        )
        select jsonb_agg(to_jsonb(reviewer_rows) order by escapes_per_1000_changes desc, approval_count desc)
        from (
          select *
          from reviewer_rows
          order by escapes_per_1000_changes desc nulls last, approval_count desc
          limit 50
        ) reviewer_rows
      ), '[]'::jsonb),
      'top_components', coalesce((
        select jsonb_agg(jsonb_build_object('component', component, 'count', count) order by count desc)
        from (
          select doc->>'value' as component, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata' and doc->>'namespace' = 'code.component' and doc->>'key' = 'name'
          group by 1
          order by count desc
          limit 30
        ) rows
      ), '[]'::jsonb),
      'top_files', coalesce((
        select jsonb_agg(jsonb_build_object('path', path, 'count', count) order by count desc)
        from (
          select doc->>'value' as path, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata' and doc->>'namespace' = 'code.file' and doc->>'key' = 'path'
          group by 1
          order by count desc
          limit 30
        ) rows
      ), '[]'::jsonb),
      'metadata_link_samples', coalesce((select jsonb_agg(item) from link_samples), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

function queryRepointelLociAnalytics() {
  const sql = `
    select jsonb_build_object(
      'review_friction_changes', coalesce((
        with
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
            coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
            and coalesce(doc->'payload'->>'_number', '') <> ''
        ),
        patch_stats as (
          select
            doc->>'context_external_id' as change_number,
            max(coalesce(nullif(doc->>'patch_set', ''), '0')::bigint) as patch_sets,
            count(*) filter (where coalesce(doc->>'automated', 'false') = 'true')::bigint as automated_messages,
            count(*) filter (where coalesce(doc->>'automated', 'false') <> 'true')::bigint as human_messages,
            count(distinct nullif(doc->>'file_path', ''))::bigint as touched_files
          from repointel_records
          where collection = 'arts'
            and doc->>'type' = 'code_review_message'
            and coalesce(doc->>'context_external_id', '') <> ''
          group by 1
        ),
        vote_stats as (
          select
            a.doc->>'context_external_id' as change_number,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) > 0
            )::bigint as positive_votes,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) < 0
            )::bigint as negative_votes,
            count(distinct nullif(a.doc->>'author_id', ''))::bigint as reviewers
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'review.approval'
            and m.doc->>'key' = 'vote'
            and coalesce(a.doc->>'context_external_id', '') <> ''
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by friction_score desc, unresolved_comments desc, total_comments desc)
        from (
          select
            c.change_number,
            left(c.subject, 120) as subject,
            c.status,
            coalesce(p.patch_sets, 0)::bigint as patch_sets,
            c.total_comments,
            c.unresolved_comments,
            coalesce(p.human_messages, 0)::bigint as human_messages,
            coalesce(p.automated_messages, 0)::bigint as automated_messages,
            coalesce(p.touched_files, 0)::bigint as touched_files,
            coalesce(v.positive_votes, 0)::bigint as positive_votes,
            coalesce(v.negative_votes, 0)::bigint as negative_votes,
            coalesce(v.reviewers, 0)::bigint as reviewers,
            (
              c.unresolved_comments * 6
              + c.total_comments * 2
              + coalesce(p.patch_sets, 0) * 5
              + coalesce(v.negative_votes, 0) * 8
            )::bigint as friction_score
          from change_rows c
          left join patch_stats p on p.change_number = c.change_number
          left join vote_stats v on v.change_number = c.change_number
          where c.total_comments > 0
             or c.unresolved_comments > 0
             or coalesce(p.patch_sets, 0) > 0
             or coalesce(v.negative_votes, 0) > 0
          order by friction_score desc, c.unresolved_comments desc, c.total_comments desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'change_churn_hotspots', coalesce((
        with
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'insertions', ''), '0')::bigint as insertions,
            coalesce(nullif(doc->'payload'->>'deletions', ''), '0')::bigint as deletions,
            coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
            coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
            and coalesce(doc->'payload'->>'_number', '') <> ''
        ),
        patch_stats as (
          select
            doc->>'context_external_id' as change_number,
            max(coalesce(nullif(doc->>'patch_set', ''), '0')::bigint) as patch_sets,
            count(distinct nullif(doc->>'file_path', ''))::bigint as touched_files
          from repointel_records
          where collection = 'arts'
            and doc->>'type' = 'code_review_message'
            and coalesce(doc->>'context_external_id', '') <> ''
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by churn_score desc, changed_lines desc, patch_sets desc)
        from (
          select
            c.change_number,
            left(c.subject, 120) as subject,
            c.status,
            c.insertions,
            c.deletions,
            (c.insertions + c.deletions)::bigint as changed_lines,
            c.total_comments,
            c.unresolved_comments,
            coalesce(p.patch_sets, 0)::bigint as patch_sets,
            coalesce(p.touched_files, 0)::bigint as touched_files,
            (
              (c.insertions + c.deletions)
              + coalesce(p.patch_sets, 0) * 20
              + c.unresolved_comments * 30
            )::bigint as churn_score
          from change_rows c
          left join patch_stats p on p.change_number = c.change_number
          where (c.insertions + c.deletions) > 0 or coalesce(p.patch_sets, 0) > 0
          order by churn_score desc, changed_lines desc, patch_sets desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'contradicted_approval_changes', coalesce((
        with
        vote_stats as (
          select
            a.doc->>'context_external_id' as change_number,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) > 0
            )::bigint as positive_votes,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) < 0
            )::bigint as negative_votes,
            count(distinct nullif(a.doc->>'author_id', ''))::bigint as reviewers
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'review.approval'
            and m.doc->>'key' = 'vote'
            and coalesce(a.doc->>'context_external_id', '') <> ''
          group by 1
        ),
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
            and coalesce(doc->'payload'->>'_number', '') <> ''
        )
        select jsonb_agg(to_jsonb(rows) order by contradiction_score desc, negative_votes desc, positive_votes desc)
        from (
          select
            v.change_number,
            left(c.subject, 120) as subject,
            c.status,
            v.reviewers,
            v.positive_votes,
            v.negative_votes,
            coalesce(c.unresolved_comments, 0)::bigint as unresolved_comments,
            (least(v.positive_votes, v.negative_votes) * 10 + coalesce(c.unresolved_comments, 0) * 3)::bigint as contradiction_score
          from vote_stats v
          left join change_rows c on c.change_number = v.change_number
          where v.positive_votes > 0 and v.negative_votes > 0
          order by contradiction_score desc, v.negative_votes desc, v.positive_votes desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'cross_artifact_convergence', coalesce((
        with
        art_rows as (
          select
            id as art_id,
            doc->>'context_external_id' as change_number,
            coalesce(doc->>'automated', 'false') = 'true' as automated
          from repointel_records
          where collection = 'arts'
            and doc->>'type' = 'code_review_message'
            and coalesce(doc->>'context_external_id', '') <> ''
        ),
        aggregate_rows as (
          select
            a.change_number,
            count(*)::bigint as review_messages,
            count(*) filter (where automated)::bigint as automated_messages,
            count(*) filter (where not automated)::bigint as human_messages,
            count(distinct case when m.doc->>'namespace' = 'security.signal' then a.art_id end)::bigint as security_signal_messages,
            count(*) filter (where m.doc->>'namespace' = 'review.approval' and m.doc->>'key' = 'vote')::bigint as vote_events,
            count(distinct case when m.doc->>'namespace' = 'code.component' and m.doc->>'key' = 'name' then m.doc->>'value' end)::bigint as components,
            count(distinct case when m.doc->>'namespace' = 'code.file' and m.doc->>'key' = 'path' then m.doc->>'value' end)::bigint as files
          from art_rows a
          left join repointel_records m
            on m.collection = 'metadata'
           and m.doc->>'subject_type' = 'art'
           and m.doc->>'subject_id' = a.art_id
          group by 1
        ),
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
        )
        select jsonb_agg(to_jsonb(rows) order by convergence_score desc, security_signal_messages desc, vote_events desc)
        from (
          select
            a.change_number,
            left(c.subject, 120) as subject,
            c.status,
            a.review_messages,
            a.human_messages,
            a.automated_messages,
            a.security_signal_messages,
            a.vote_events,
            a.components,
            a.files,
            (
              case when a.security_signal_messages > 0 then 20 else 0 end
              + case when a.vote_events > 0 then 12 else 0 end
              + case when a.components > 0 then 8 else 0 end
              + case when a.files > 0 then 8 else 0 end
              + least(a.review_messages, 20)
            )::bigint as convergence_score
          from aggregate_rows a
          left join change_rows c on c.change_number = a.change_number
          where a.review_messages > 0
          order by convergence_score desc, a.security_signal_messages desc, a.vote_events desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'review_abandonment_changes', coalesce((
        with
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
            coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
            and coalesce(doc->'payload'->>'_number', '') <> ''
        ),
        patch_stats as (
          select
            doc->>'context_external_id' as change_number,
            max(coalesce(nullif(doc->>'patch_set', ''), '0')::bigint) as patch_sets,
            count(*) filter (where coalesce(doc->>'automated', 'false') <> 'true')::bigint as human_messages
          from repointel_records
          where collection = 'arts'
            and doc->>'type' = 'code_review_message'
            and coalesce(doc->>'context_external_id', '') <> ''
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by abandonment_score desc, patch_sets desc, unresolved_comments desc)
        from (
          select
            c.change_number,
            left(c.subject, 120) as subject,
            c.status,
            coalesce(p.patch_sets, 0)::bigint as patch_sets,
            c.total_comments,
            c.unresolved_comments,
            coalesce(p.human_messages, 0)::bigint as human_messages,
            (
              case when c.status in ('ABANDONED', 'NEW') then 15 else 0 end
              + c.unresolved_comments * 6
              + c.total_comments * 2
              + coalesce(p.patch_sets, 0) * 4
            )::bigint as abandonment_score
          from change_rows c
          left join patch_stats p on p.change_number = c.change_number
          where c.status in ('ABANDONED', 'NEW')
          order by abandonment_score desc, patch_sets desc, unresolved_comments desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'bug_thread_hotspots', coalesce((
        select jsonb_agg(to_jsonb(rows) order by exposure_score desc, heat desc, message_count desc)
        from (
          select
            id as raw_record_id,
            coalesce(nullif(doc->'payload'->>'id', ''), doc->>'external_id', id) as bug_id,
            left(coalesce(doc->'payload'->>'title', doc->'payload'->>'description', id), 120) as title,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'importance', ''), 'UNKNOWN') as importance,
            coalesce(nullif(doc->'payload'->>'heat', ''), '0')::bigint as heat,
            coalesce(nullif(doc->'payload'->>'message_count', ''), '0')::bigint as message_count,
            coalesce(nullif(doc->'payload'->>'number_of_duplicates', ''), '0')::bigint as duplicate_count,
            coalesce(nullif(doc->'payload'->>'users_affected_count', ''), '0')::bigint as users_affected_count,
            case when coalesce(doc->'payload'->>'security_related', 'false') = 'true' then true else false end as security_related,
            case when coalesce(doc->'payload'->>'private', 'false') = 'true' then true else false end as private_bug,
            (
              coalesce(nullif(doc->'payload'->>'heat', ''), '0')::bigint
              + coalesce(nullif(doc->'payload'->>'message_count', ''), '0')::bigint
              + coalesce(nullif(doc->'payload'->>'number_of_duplicates', ''), '0')::bigint * 4
              + coalesce(nullif(doc->'payload'->>'users_affected_count', ''), '0')::bigint * 3
              + case when coalesce(doc->'payload'->>'security_related', 'false') = 'true' then 25 else 0 end
              + case when coalesce(doc->'payload'->>'private', 'false') = 'true' then 15 else 0 end
            )::bigint as exposure_score
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'launchpad_bug'
          order by exposure_score desc, heat desc, message_count desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'component_concentration', coalesce((
        with
        component_rows as (
          select
            m.doc->>'value' as component,
            a.doc->>'author_id' as author_id,
            a.doc->>'context_external_id' as change_number
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'code.component'
            and m.doc->>'key' = 'name'
            and m.doc->>'value' ~ '[a-z]'
        ),
        security_rows as (
          select
            comp.doc->>'value' as component,
            count(distinct sig.doc->>'subject_id')::bigint as security_signal_reviews
          from repointel_records sig
          join repointel_records comp
            on comp.collection = 'metadata'
           and comp.doc->>'subject_type' = 'art'
           and comp.doc->>'subject_id' = sig.doc->>'subject_id'
           and comp.doc->>'namespace' = 'code.component'
           and comp.doc->>'key' = 'name'
          where sig.collection = 'metadata'
            and sig.doc->>'subject_type' = 'art'
            and sig.doc->>'namespace' = 'security.signal'
            and comp.doc->>'value' ~ '[a-z]'
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by concentration_score desc, review_changes desc)
        from (
          select
            c.component,
            count(distinct c.change_number)::bigint as review_changes,
            count(distinct nullif(c.author_id, ''))::bigint as distinct_authors,
            coalesce(s.security_signal_reviews, 0)::bigint as security_signal_reviews,
            round((count(distinct c.change_number)::numeric / nullif(count(distinct nullif(c.author_id, '')), 0)), 2) as changes_per_author,
            (
              coalesce(s.security_signal_reviews, 0) * 5
              + count(distinct c.change_number)
              + least(count(distinct c.change_number), 200) / greatest(count(distinct nullif(c.author_id, '')), 1)
            )::bigint as concentration_score
          from component_rows c
          left join security_rows s on s.component = c.component
          group by 1, s.security_signal_reviews
          order by concentration_score desc, review_changes desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'component_hotspots', coalesce((
        with
        component_changes as (
          select
            comp.doc->>'value' as component,
            a.doc->>'context_external_id' as change_number
          from repointel_records comp
          join repointel_records a
            on a.collection = 'arts'
           and a.id = comp.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where comp.collection = 'metadata'
            and comp.doc->>'subject_type' = 'art'
            and comp.doc->>'namespace' = 'code.component'
            and comp.doc->>'key' = 'name'
            and comp.doc->>'value' ~ '[a-z]'
            and coalesce(a.doc->>'context_external_id', '') <> ''
        ),
        security_signal_reviews as (
          select
            comp.doc->>'value' as component,
            count(distinct sig.doc->>'subject_id')::bigint as security_signal_reviews
          from repointel_records sig
          join repointel_records comp
            on comp.collection = 'metadata'
           and comp.doc->>'subject_type' = 'art'
           and comp.doc->>'subject_id' = sig.doc->>'subject_id'
           and comp.doc->>'namespace' = 'code.component'
           and comp.doc->>'key' = 'name'
          where sig.collection = 'metadata'
            and sig.doc->>'subject_type' = 'art'
            and sig.doc->>'namespace' = 'security.signal'
            and comp.doc->>'value' ~ '[a-z]'
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by hotspot_score desc, review_changes desc)
        from (
          select
            cc.component,
            count(distinct cc.change_number)::bigint as review_changes,
            coalesce(ss.security_signal_reviews, 0)::bigint as security_signal_reviews,
            (coalesce(ss.security_signal_reviews, 0) * 6 + count(distinct cc.change_number))::bigint as hotspot_score
          from component_changes cc
          left join security_signal_reviews ss on ss.component = cc.component
          group by 1, ss.security_signal_reviews
          order by hotspot_score desc, review_changes desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'review_automation_balance', coalesce((
        with
        art_rows as (
          select
            doc->>'context_external_id' as change_number,
            coalesce(doc->>'automated', 'false') = 'true' as automated
          from repointel_records
          where collection = 'arts'
            and doc->>'type' = 'code_review_message'
            and coalesce(doc->>'context_external_id', '') <> ''
        ),
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
        )
        select jsonb_agg(to_jsonb(rows) order by automated_ratio desc, total_messages desc)
        from (
          select
            a.change_number,
            left(c.subject, 120) as subject,
            c.status,
            count(*)::bigint as total_messages,
            count(*) filter (where a.automated)::bigint as automated_messages,
            count(*) filter (where not a.automated)::bigint as human_messages,
            round((count(*) filter (where a.automated))::numeric / nullif(count(*), 0), 3) as automated_ratio
          from art_rows a
          left join change_rows c on c.change_number = a.change_number
          group by 1, 2, 3
          having count(*) >= 5
          order by automated_ratio desc, total_messages desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'dependency_hotspots', coalesce((
        select jsonb_agg(to_jsonb(rows) order by hotspot_score desc, touched_changes desc)
        from (
          select
            doc->>'value' as path,
            count(*)::bigint as touched_changes,
            count(distinct doc->>'subject_id')::bigint as distinct_subjects,
            count(*)::bigint as hotspot_score
          from repointel_records
          where collection = 'metadata'
            and doc->>'namespace' = 'code.file'
            and doc->>'key' = 'path'
            and (
              doc->>'value' ilike '%requirements%'
              or doc->>'value' ilike '%package.json%'
              or doc->>'value' ilike '%package-lock.json%'
              or doc->>'value' ilike '%setup.py%'
              or doc->>'value' ilike '%setup.cfg%'
              or doc->>'value' ilike '%pyproject.toml%'
              or doc->>'value' ilike '%tox.ini%'
              or doc->>'value' ilike '%go.mod%'
              or doc->>'value' ilike '%go.sum%'
            )
          group by 1
          order by hotspot_score desc, touched_changes desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'workflow_hotspots', coalesce((
        select jsonb_agg(to_jsonb(rows) order by hotspot_score desc, touched_changes desc)
        from (
          select
            doc->>'value' as path,
            count(*)::bigint as touched_changes,
            count(distinct doc->>'subject_id')::bigint as distinct_subjects,
            count(*)::bigint as hotspot_score
          from repointel_records
          where collection = 'metadata'
            and doc->>'namespace' = 'code.file'
            and doc->>'key' = 'path'
            and (
              doc->>'value' ilike '%.github/workflows%'
              or doc->>'value' ilike '%zuul%'
              or doc->>'value' ilike '%jenkins%'
              or doc->>'value' ilike '%tox.ini%'
            )
          group by 1
          order by hotspot_score desc, touched_changes desc
          limit 25
        ) rows
      ), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

function queryRepointelLociExtendedAnalytics() {
  const sql = `
    select jsonb_build_object(
      'silent_security_fix_candidates', coalesce((
        with
        signal_rows as (
          select
            a.id as art_id,
            a.doc->>'author_id' as author_id,
            left(coalesce(a.doc->>'body', ''), 160) as body_preview,
            count(*)::bigint as security_signal_mentions,
            count(distinct m.doc->>'key')::bigint as distinct_signal_kinds
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'commit_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'security.signal'
          group by 1, 2, 3
        ),
        commit_rows as (
          select
            m.doc->>'subject_id' as art_id,
            max(case when m.doc->>'namespace' = 'git.commit' and m.doc->>'key' = 'sha' then m.doc->>'value' end) as commit_sha,
            bool_or(m.doc->>'namespace' = 'security.identifier' and m.doc->>'key' in ('cve', 'ghsa')) as has_explicit_identifier
          from repointel_records m
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'subject_id' in (select art_id from signal_rows)
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by candidate_score desc, security_signal_mentions desc)
        from (
          select
            s.art_id,
            left(coalesce(c.commit_sha, s.art_id), 16) as commit_sha,
            s.author_id,
            s.security_signal_mentions,
            s.distinct_signal_kinds,
            s.body_preview,
            (s.security_signal_mentions * 4 + s.distinct_signal_kinds * 10)::bigint as candidate_score
          from signal_rows s
          left join commit_rows c on c.art_id = s.art_id
          where coalesce(c.has_explicit_identifier, false) = false
          order by candidate_score desc, security_signal_mentions desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'file_hotspots', coalesce((
        with
        file_changes as (
          select
            f.doc->>'value' as path,
            a.doc->>'context_external_id' as change_number
          from repointel_records f
          join repointel_records a
            on a.collection = 'arts'
           and a.id = f.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where f.collection = 'metadata'
            and f.doc->>'subject_type' = 'art'
            and f.doc->>'namespace' = 'code.file'
            and f.doc->>'key' = 'path'
            and coalesce(a.doc->>'context_external_id', '') <> ''
            and f.doc->>'value' not ilike '%PATCHSET_LEVEL%'
        ),
        security_rows as (
          select
            f.doc->>'value' as path,
            count(distinct sig.doc->>'subject_id')::bigint as security_signal_reviews
          from repointel_records sig
          join repointel_records f
            on f.collection = 'metadata'
           and f.doc->>'subject_type' = 'art'
           and f.doc->>'subject_id' = sig.doc->>'subject_id'
           and f.doc->>'namespace' = 'code.file'
           and f.doc->>'key' = 'path'
          where sig.collection = 'metadata'
            and sig.doc->>'subject_type' = 'art'
            and sig.doc->>'namespace' = 'security.signal'
            and f.doc->>'value' not ilike '%PATCHSET_LEVEL%'
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by hotspot_score desc, review_changes desc)
        from (
          select
            fc.path,
            count(distinct fc.change_number)::bigint as review_changes,
            coalesce(sr.security_signal_reviews, 0)::bigint as security_signal_reviews,
            (coalesce(sr.security_signal_reviews, 0) * 6 + count(distinct fc.change_number))::bigint as hotspot_score
          from file_changes fc
          left join security_rows sr on sr.path = fc.path
          group by 1, sr.security_signal_reviews
          order by hotspot_score desc, review_changes desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'sensitive_review_disagreement', coalesce((
        with
        vote_rows as (
          select
            a.doc->>'context_external_id' as change_number,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) > 0
            )::bigint as positive_votes,
            count(*) filter (
              where m.doc->'value'->>'action' = 'vote'
                and coalesce((m.doc->'value'->>'value')::int, 0) < 0
            )::bigint as negative_votes
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'review.approval'
            and m.doc->>'key' = 'vote'
            and coalesce(a.doc->>'context_external_id', '') <> ''
          group by 1
        ),
        signal_rows as (
          select
            a.doc->>'context_external_id' as change_number,
            count(*)::bigint as security_signal_mentions,
            count(distinct m.doc->>'key')::bigint as distinct_signal_kinds
          from repointel_records m
          join repointel_records a
            on a.collection = 'arts'
           and a.id = m.doc->>'subject_id'
           and a.doc->>'type' = 'code_review_message'
          where m.collection = 'metadata'
            and m.doc->>'subject_type' = 'art'
            and m.doc->>'namespace' = 'security.signal'
            and coalesce(a.doc->>'context_external_id', '') <> ''
          group by 1
        ),
        change_rows as (
          select
            doc->'payload'->>'_number' as change_number,
            coalesce(nullif(doc->'payload'->>'subject', ''), doc->'payload'->>'project', doc->>'id') as subject,
            coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
            coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
          from repointel_records
          where collection = 'raw-records'
            and doc->>'record_type' = 'gerrit_change'
        )
        select jsonb_agg(to_jsonb(rows) order by disagreement_score desc, negative_votes desc, security_signal_mentions desc)
        from (
          select
            v.change_number,
            left(c.subject, 120) as subject,
            c.status,
            coalesce(c.unresolved_comments, 0)::bigint as unresolved_comments,
            v.positive_votes,
            v.negative_votes,
            s.security_signal_mentions,
            s.distinct_signal_kinds,
            (least(v.positive_votes, v.negative_votes) * 10 + s.security_signal_mentions * 6 + coalesce(c.unresolved_comments, 0) * 3)::bigint as disagreement_score
          from vote_rows v
          join signal_rows s on s.change_number = v.change_number
          left join change_rows c on c.change_number = v.change_number
          where v.positive_votes > 0 and v.negative_votes > 0
          order by disagreement_score desc, v.negative_votes desc, s.security_signal_mentions desc
          limit 25
        ) rows
      ), '[]'::jsonb),
      'sensitive_surface_hotspots', coalesce((
        with
        signal_components as (
          select
            comp.doc->>'value' as component,
            count(distinct sig.doc->>'subject_id')::bigint as security_signal_reviews,
            count(distinct nullif(sig.doc->>'key', ''))::bigint as distinct_signal_kinds
          from repointel_records sig
          join repointel_records comp
            on comp.collection = 'metadata'
           and comp.doc->>'subject_type' = 'art'
           and comp.doc->>'subject_id' = sig.doc->>'subject_id'
           and comp.doc->>'namespace' = 'code.component'
           and comp.doc->>'key' = 'name'
          where sig.collection = 'metadata'
            and sig.doc->>'subject_type' = 'art'
            and sig.doc->>'namespace' = 'security.signal'
            and comp.doc->>'value' ~ '[a-z]'
          group by 1
        )
        select jsonb_agg(to_jsonb(rows) order by hotspot_score desc, security_signal_reviews desc)
        from (
          select
            sc.component,
            sc.security_signal_reviews,
            sc.distinct_signal_kinds,
            (sc.security_signal_reviews * 6 + sc.distinct_signal_kinds * 10)::bigint as hotspot_score
          from signal_components sc
          group by 1, 2, 3
          order by hotspot_score desc, security_signal_reviews desc
          limit 25
        ) rows
      ), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

function queryRepointelIdeasBase(options = {}) {
  const minCommits = Math.max(1, Number(options.minCommits || 10));
  const minApprovals = Math.max(1, Number(options.minApprovals || 10));
  const sql = `
    with link_samples as (
      select jsonb_build_object(
        'origin', r.doc->>'origin',
        'relation', r.doc->>'relation',
        'from_namespace', mf.doc->>'namespace',
        'from_key', mf.doc->>'key',
        'from_value', left(mf.doc->>'value', 160),
        'to_namespace', mt.doc->>'namespace',
        'to_key', mt.doc->>'key',
        'to_value', left(mt.doc->>'value', 160)
      ) as item
      from repointel_records r
      join repointel_records mf on mf.collection = 'metadata' and mf.id = r.doc->>'from_id'
      join repointel_records mt on mt.collection = 'metadata' and mt.id = r.doc->>'to_id'
      where r.collection = 'relationships'
        and r.doc->>'origin' like 'normalizer.metadata_link.%'
      order by r.updated_at desc
      limit 25
    )
    select jsonb_build_object(
      'generated_at', now(),
      'metadata_by_namespace_key', coalesce((
        select jsonb_agg(jsonb_build_object('namespace', namespace, 'key', key, 'count', count) order by count desc)
        from (
          select doc->>'namespace' as namespace, doc->>'key' as key, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata'
          group by 1, 2
          order by count desc
          limit 80
        ) rows
      ), '[]'::jsonb),
      'relationship_by_origin', coalesce((
        select jsonb_agg(jsonb_build_object('origin', origin, 'count', count) order by count desc)
        from (
          select coalesce(nullif(doc->>'origin', ''), '(none)') as origin, count(*)::bigint as count
          from repointel_records
          where collection = 'relationships'
          group by 1
          order by count desc
          limit 60
        ) rows
      ), '[]'::jsonb),
      'relationship_by_relation', coalesce((
        select jsonb_agg(jsonb_build_object('relation', relation, 'from_type', from_type, 'to_type', to_type, 'count', count) order by count desc)
        from (
          select doc->>'relation' as relation, doc->>'from_type' as from_type, doc->>'to_type' as to_type, count(*)::bigint as count
          from repointel_records
          where collection = 'relationships'
          group by 1, 2, 3
          order by count desc
          limit 60
        ) rows
      ), '[]'::jsonb),
      'security_signals', coalesce((
        select jsonb_agg(jsonb_build_object('key', key, 'count', count) order by count desc)
        from (
          select doc->>'key' as key, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata' and doc->>'namespace' = 'security.signal'
          group by 1
        ) rows
      ), '[]'::jsonb),
      'idea_signal_counts', coalesce((
        select jsonb_agg(jsonb_build_object('signal', signal, 'count', count) order by signal)
        from (
          select 'authors' as signal, count(*)::bigint as count
          from repointel_records where collection = 'authors'
          union all
          select 'arts', count(*)::bigint from repointel_records where collection = 'arts'
          union all
          select 'bug_nodes', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'issue.launchpad' and doc->>'key' = 'bug_id'
          union all
          select 'bug_lifecycle', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'issue.launchpad' and doc->>'key' in ('date_created', 'date_last_updated', 'date_last_message', 'message_count', 'security_related', 'duplicate_count', 'information_type')
          union all
          select 'commit_shas', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'git.commit' and doc->>'key' = 'sha'
          union all
          select 'review_votes', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'review.approval' and doc->>'key' in ('vote', 'submit_record_label')
          union all
          select 'review_author_links', count(*)::bigint from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_author_link.v1'
          union all
          select 'commit_bug_links', count(*)::bigint from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.commit_bug'
          union all
          select 'change_commit_links', count(*)::bigint from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_commit'
          union all
          select 'change_file_links', count(*)::bigint from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_file'
          union all
          select 'change_component_links', count(*)::bigint from repointel_records where collection = 'relationships' and doc->>'origin' = 'normalizer.metadata_link.gerrit_change_component'
          union all
          select 'security_signals', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'security.signal'
          union all
          select 'cve_ids', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'security.identifier' and doc->>'key' = 'cve'
          union all
          select 'file_paths', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.file' and doc->>'key' = 'path'
          union all
          select 'components', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.component' and doc->>'key' = 'name'
          union all
          select 'churn', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'git.commit' and doc->>'key' in ('insertions', 'deletions', 'changed_file_count')
          union all
          select 'branches', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code_review.gerrit' and doc->>'key' = 'branch'
          union all
          select 'ci_messages', count(*)::bigint from repointel_records where collection = 'arts' and doc->>'type' = 'code_review_message' and doc->>'automated' = 'true'
          union all
          select 'dependency_paths', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.file' and doc->>'key' = 'path' and (doc->>'value' ilike '%requirements%' or doc->>'value' ilike '%package.json%' or doc->>'value' ilike '%setup.py%' or doc->>'value' ilike '%setup.cfg%' or doc->>'value' ilike '%pyproject.toml%' or doc->>'value' ilike '%tox.ini%')
          union all
          select 'workflow_paths', count(*)::bigint from repointel_records where collection = 'metadata' and doc->>'namespace' = 'code.file' and doc->>'key' = 'path' and (doc->>'value' ilike '%.github/workflows%' or doc->>'value' ilike '%zuul%' or doc->>'value' ilike '%jenkins%')
          union all
          select 'repo_settings', 0::bigint
          union all
          select 'release_boundaries', 0::bigint
        ) rows
      ), '[]'::jsonb),
      'author_defect_density', '[]'::jsonb,
      'reviewer_defect_escape_density', '[]'::jsonb,
      'top_components', coalesce((
        select jsonb_agg(jsonb_build_object('component', component, 'count', count) order by count desc)
        from (
          select doc->>'value' as component, count(*)::bigint as count
          from repointel_records
          where collection = 'metadata' and doc->>'namespace' = 'code.component' and doc->>'key' = 'name'
          group by 1
          order by count desc
          limit 30
        ) rows
      ), '[]'::jsonb),
      'metadata_link_samples', coalesce((select jsonb_agg(item) from link_samples), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

function queryRepointelAuthorHistory(options = {}) {
  const limit = Math.min(500, Math.max(1, Number(options.limit || 50)));
  const reviewLimit = Math.min(500, Math.max(1, Number(options.reviewLimit || 100)));
  const commitLimit = Math.min(500, Math.max(1, Number(options.commitLimit || 100)));
  const bugLimit = Math.min(200, Math.max(1, Number(options.bugLimit || 50)));
  const includeBugs = options.includeBugs !== false;
  const sql = `
    with
    raw_input as (
      select
        ${sqlLiteral(options.q || "")}::text as q,
        ${sqlLiteral(options.name || "")}::text as name,
        ${sqlLiteral(options.lastName || "")}::text as last_name,
        lower(${sqlLiteral(options.email || "")}::text) as email,
        ${sqlLiteral(options.authorId || "")}::text as author_id,
        lower(${sqlLiteral(options.externalAuthorId || "")}::text) as external_author_id,
        ${sqlLiteral(options.gerritAccountId || "")}::text as gerrit_account_id,
        ${sqlLiteral(options.changeNumber || "")}::text as change_number,
        ${sqlLiteral(options.repositoryId || "")}::text as repository_id,
        ${sqlLiteral(options.project || "")}::text as project,
        ${includeBugs ? "true" : "false"}::boolean as include_bugs
    ),
    input as (
      select
        *,
        regexp_replace(lower(q), '[^a-z0-9]+', '', 'g') as q_key,
        regexp_replace(lower(regexp_replace(q, '^.*\\s+', '')), '[^a-z0-9]+', '', 'g') as q_last_name_key,
        regexp_replace(lower(name), '[^a-z0-9]+', '', 'g') as name_key,
        regexp_replace(lower(regexp_replace(name, '^.*\\s+', '')), '[^a-z0-9]+', '', 'g') as name_last_name_key,
        regexp_replace(lower(last_name), '[^a-z0-9]+', '', 'g') as last_name_key
      from raw_input
    ),
    author_rows as materialized (
      select
        a.id,
        coalesce(a.doc->>'repository_id', '') as repository_id,
        coalesce(a.doc->>'external_author_id', '') as external_author_id,
        split_part(coalesce(a.doc->>'external_author_id', ''), ':', 1) as provider,
        coalesce(a.doc->>'display_name', a.doc->>'name', a.doc->>'email', a.doc->>'username', a.id) as display_name,
        coalesce(a.doc->>'name', '') as name,
        coalesce(a.doc->>'username', '') as username,
        lower(coalesce(a.doc->>'email', '')) as email,
        coalesce(a.doc->>'profile_url', '') as profile_url,
        regexp_replace(lower(coalesce(a.doc->>'display_name', a.doc->>'name', '')), '[^a-z0-9]+', '', 'g') as name_key,
        regexp_replace(lower(regexp_replace(coalesce(a.doc->>'display_name', a.doc->>'name', ''), '^.*\\s+', '')), '[^a-z0-9]+', '', 'g') as last_name_key,
        regexp_replace(lower(split_part(coalesce(a.doc->>'email', replace(a.doc->>'external_author_id', 'git:', '')), '@', 1)), '[^a-z0-9]+', '', 'g') as email_local_key
      from repointel_records a, input i
      where a.collection = 'authors'
        and (i.repository_id = '' or a.doc->>'repository_id' = i.repository_id)
    ),
    change_owner_seed as materialized (
      select
        'gerrit:' || coalesce(r.doc->'payload'->'owner'->>'_account_id', '') as external_author_id,
        r.doc->>'repository_id' as repository_id
      from repointel_records r, input i
      where i.change_number <> ''
        and r.collection = 'raw-records'
        and r.doc->>'record_type' = 'gerrit_change'
        and r.doc->'payload'->>'_number' = i.change_number
        and (i.repository_id = '' or r.doc->>'repository_id' = i.repository_id)
        and (i.project = '' or coalesce(nullif(r.doc->'payload'->>'project', ''), '') = i.project)
    ),
    direct_matches as materialized (
      select distinct
        a.*,
        case
          when i.author_id <> '' and a.id = i.author_id then 'author_id'
          when i.external_author_id <> '' and lower(a.external_author_id) = i.external_author_id then 'external_author_id'
          when i.gerrit_account_id <> '' and a.external_author_id = 'gerrit:' || i.gerrit_account_id then 'gerrit_account_id'
          when i.email <> '' and a.email = i.email then 'email'
          when i.name <> '' and lower(a.display_name) = lower(i.name) then 'name'
          when i.name_key <> '' and a.name_key = i.name_key then 'name_normalized'
          when i.last_name_key <> '' and a.last_name_key = i.last_name_key then 'last_name'
          when i.name_last_name_key <> '' and a.last_name_key = i.name_last_name_key then 'name_last_name'
          when i.q <> '' and (
            lower(a.display_name) like '%' || lower(i.q) || '%'
            or lower(a.email) like '%' || lower(i.q) || '%'
            or lower(a.external_author_id) like '%' || lower(i.q) || '%'
            or lower(a.username) like '%' || lower(i.q) || '%'
          ) then 'query'
          when i.q_key <> '' and a.name_key = i.q_key then 'query_name_normalized'
          when i.q_last_name_key <> '' and a.last_name_key = i.q_last_name_key then 'query_last_name'
          else 'change_owner'
        end as match_method
      from author_rows a, input i
      where (i.author_id <> '' and a.id = i.author_id)
         or (i.external_author_id <> '' and lower(a.external_author_id) = i.external_author_id)
         or (i.gerrit_account_id <> '' and a.external_author_id = 'gerrit:' || i.gerrit_account_id)
         or (i.email <> '' and a.email = i.email)
         or (i.name <> '' and lower(a.display_name) = lower(i.name))
         or (i.name_key <> '' and a.name_key = i.name_key)
         or (i.last_name_key <> '' and a.last_name_key = i.last_name_key)
         or (i.name_last_name_key <> '' and a.last_name_key = i.name_last_name_key)
         or (i.q <> '' and (
              lower(a.display_name) like '%' || lower(i.q) || '%'
              or lower(a.email) like '%' || lower(i.q) || '%'
              or lower(a.external_author_id) like '%' || lower(i.q) || '%'
              or lower(a.username) like '%' || lower(i.q) || '%'
            ))
         or (i.q_key <> '' and a.name_key = i.q_key)
         or (i.q_last_name_key <> '' and a.last_name_key = i.q_last_name_key)
         or exists (
              select 1
              from change_owner_seed cos
              where cos.repository_id = a.repository_id
                and cos.external_author_id = a.external_author_id
            )
    ),
    matched_authors as materialized (
      select distinct on (id)
        id,
        repository_id,
        external_author_id,
        provider,
        display_name,
        name,
        username,
        email,
        profile_url,
        match_method
      from (
        select * from direct_matches
        union all
        select
          a.*,
          case
            when d.email <> '' and a.email = d.email then 'same_repo_email'
            when d.name_key <> '' and a.name_key = d.name_key then 'same_repo_name'
            when d.last_name_key <> '' and a.last_name_key = d.last_name_key then 'same_repo_last_name'
            when d.email_local_key <> '' and a.email_local_key = d.email_local_key then 'same_repo_email_localpart'
            else 'same_repo_identity'
          end as match_method
        from author_rows a
        join direct_matches d
          on d.repository_id = a.repository_id
         and a.id <> d.id
         and (
           (d.email <> '' and a.email = d.email)
           or (d.name_key <> '' and a.name_key = d.name_key)
           or (d.last_name_key <> '' and a.last_name_key = d.last_name_key)
           or (d.email_local_key <> '' and a.email_local_key = d.email_local_key)
         )
      ) rows
      order by id, case match_method
        when 'author_id' then 1
        when 'external_author_id' then 2
        when 'gerrit_account_id' then 3
        when 'change_owner' then 4
        when 'email' then 5
        when 'name' then 6
        when 'name_normalized' then 7
        when 'last_name' then 8
        when 'name_last_name' then 9
        when 'query' then 10
        when 'query_name_normalized' then 11
        when 'query_last_name' then 12
        else 20
      end
    ),
    repositories as materialized (
      select
        r.id as repository_id,
        coalesce(r.doc->>'name', r.doc->>'slug', r.id) as repository_name,
        coalesce(r.doc->>'slug', '') as repository_slug
      from repointel_records r
      where r.collection = 'repositories'
    ),
    gerrit_reviews as materialized (
      select distinct on (r.doc->>'repository_id', r.doc->'payload'->>'_number')
        r.id as raw_record_id,
        r.doc->>'repository_id' as repository_id,
        repo.repository_name,
        r.doc->'payload'->>'project' as project,
        r.doc->'payload'->>'branch' as branch,
        r.doc->'payload'->>'_number' as change_number,
        coalesce(nullif(r.doc->'payload'->>'status', ''), 'UNKNOWN') as status,
        coalesce(nullif(r.doc->'payload'->>'subject', ''), r.doc->>'id') as subject,
        coalesce(r.doc->>'url', '') as url,
        coalesce(r.doc->'payload'->'owner'->>'_account_id', '') as owner_account_id,
        coalesce(r.doc->'payload'->'owner'->>'name', '') as owner_name,
        coalesce(r.doc->'payload'->'owner'->>'email', '') as owner_email,
        left(coalesce(r.doc->'payload'->>'created', ''), 19) as created_at,
        left(coalesce(r.doc->'payload'->>'updated', ''), 19) as updated_at,
        left(coalesce(r.doc->'payload'->>'submitted', ''), 19) as submitted_at,
        coalesce(nullif(r.doc->'payload'->>'insertions', ''), '0')::bigint as insertions,
        coalesce(nullif(r.doc->'payload'->>'deletions', ''), '0')::bigint as deletions,
        coalesce(nullif(r.doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
        coalesce(nullif(r.doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments,
        coalesce(nullif(r.doc->'payload'->>'current_revision_number', ''), '0')::bigint as current_revision_number,
        coalesce(r.doc->'payload'->>'current_revision', '') as current_revision,
        coalesce(r.doc->'payload'->>'current_revision_commit_message', '') as current_revision_commit_message,
        ma.id as author_id,
        ma.external_author_id
      from repointel_records r
      join matched_authors ma
        on ma.repository_id = r.doc->>'repository_id'
       and ma.external_author_id = 'gerrit:' || coalesce(r.doc->'payload'->'owner'->>'_account_id', '')
      left join repositories repo on repo.repository_id = r.doc->>'repository_id'
      cross join input i
      where r.collection = 'raw-records'
        and r.doc->>'record_type' = 'gerrit_change'
        and (i.project = '' or coalesce(nullif(r.doc->'payload'->>'project', ''), '') = i.project)
    ),
    git_commit_identities as materialized (
      select distinct
        repository_id,
        email,
        regexp_replace(lower(display_name), '[^a-z0-9]+', '', 'g') as name_key
      from matched_authors
      where provider = 'git' or email <> ''
    ),
    git_commits as materialized (
      select distinct on (r.doc->>'repository_id', r.doc->'payload'->>'sha')
        r.id as raw_record_id,
        r.doc->>'repository_id' as repository_id,
        repo.repository_name,
        r.doc->'payload'->>'sha' as sha,
        coalesce(r.doc->'payload'->>'author_name', '') as author_name,
        lower(coalesce(r.doc->'payload'->>'author_email', '')) as author_email,
        coalesce(r.doc->'payload'->>'authored_at', r.doc->'payload'->>'author_date', '') as authored_at,
        coalesce(nullif(r.doc->'payload'->>'subject', ''), split_part(coalesce(r.doc->'payload'->>'message', ''), E'\\n', 1)) as subject,
        coalesce(r.doc->'payload'->>'message', '') as message,
        coalesce(nullif(r.doc->'payload'->>'insertions', ''), '0')::bigint as insertions,
        coalesce(nullif(r.doc->'payload'->>'deletions', ''), '0')::bigint as deletions,
        coalesce(nullif(r.doc->'payload'->>'changed_file_count', ''), '0')::bigint as changed_file_count,
        coalesce(r.doc->>'url', '') as url
      from repointel_records r
      join git_commit_identities gi
        on gi.repository_id = r.doc->>'repository_id'
       and (
         (gi.email <> '' and lower(coalesce(r.doc->'payload'->>'author_email', '')) = gi.email)
         or (
           gi.name_key <> ''
           and regexp_replace(lower(coalesce(r.doc->'payload'->>'author_name', '')), '[^a-z0-9]+', '', 'g') = gi.name_key
         )
       )
      left join repositories repo on repo.repository_id = r.doc->>'repository_id'
      where r.collection = 'raw-records'
        and r.doc->>'record_type' = 'git_commit'
    ),
    line_survival as materialized (
      select
        ma.id as author_id,
        ma.repository_id,
        repo.repository_name,
        ma.display_name,
        ma.email,
        ma.external_author_id,
        m.doc->'value' as value
      from matched_authors ma
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'author'
       and m.doc->>'subject_id' = ma.id
       and m.doc->>'namespace' = 'git.line_survival'
       and m.doc->>'key' = 'summary'
      left join repositories repo on repo.repository_id = ma.repository_id
    ),
    authored_bug_messages as materialized (
      select
        a.id as art_id,
        a.doc->>'raw_record_id' as bug_raw_record_id,
        a.doc->>'context_external_id' as bug_id,
        a.doc->>'author_id' as author_id,
        ma.repository_id,
        coalesce(a.doc->>'source_created_at', a.doc->>'created_at', '') as created_at,
        left(coalesce(a.doc->>'body', ''), 500) as body_preview
      from repointel_records a
      join matched_authors ma on ma.id = a.doc->>'author_id'
      cross join input i
      where i.include_bugs = true
        and a.collection = 'arts'
        and a.doc->>'type' = 'bug_message'
    ),
    linked_bug_review_messages as materialized (
      select
        a.id as art_id,
        a.doc->>'raw_record_id' as bug_raw_record_id,
        a.doc->>'context_external_id' as bug_id,
        gr.repository_id,
        gr.change_number,
        gr.url as review_url,
        gr.subject as review_subject,
        coalesce(a.doc->>'source_created_at', a.doc->>'created_at', '') as created_at,
        left(coalesce(a.doc->>'body', ''), 500) as body_preview
      from repointel_records a
      join gerrit_reviews gr
        on position('/+/' || gr.change_number in coalesce(a.doc->>'body', '')) > 0
        or position('/+' || gr.change_number in coalesce(a.doc->>'body', '')) > 0
      cross join input i
      where i.include_bugs = true
        and a.collection = 'arts'
        and a.doc->>'type' = 'bug_message'
    ),
    review_bug_refs as materialized (
      select
        gr.repository_id,
        gr.change_number as source_id,
        gr.url as source_url,
        gr.subject as source_subject,
        match[2] as bug_id
      from gerrit_reviews gr
      cross join input i
      cross join lateral regexp_matches(
        coalesce(gr.current_revision_commit_message, '') || E'\\n' || coalesce(gr.subject, ''),
        '(closes-bug|partial-bug|related-bug|bug)[^0-9]{0,30}#?([0-9]{5,})',
        'gi'
      ) as match
      where i.include_bugs = true
    ),
    commit_bug_refs as materialized (
      select
        gc.repository_id,
        gc.sha as source_id,
        gc.url as source_url,
        gc.subject as source_subject,
        match[2] as bug_id
      from git_commits gc
      cross join input i
      cross join lateral regexp_matches(
        coalesce(gc.message, '') || E'\\n' || coalesce(gc.subject, ''),
        '(closes-bug|partial-bug|related-bug|bug)[^0-9]{0,30}#?([0-9]{5,})',
        'gi'
      ) as match
      where i.include_bugs = true
    ),
    authored_art_bug_refs as materialized (
      select
        a.doc->>'repository_id' as repository_id,
        a.id as source_id,
        '' as source_url,
        a.doc->>'type' as source_subject,
        trim(both '"' from m.doc->>'value') as bug_id
      from repointel_records a
      join matched_authors ma on ma.id = a.doc->>'author_id'
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' = 'issue.launchpad'
       and m.doc->>'key' = 'bug_id'
      cross join input i
      where i.include_bugs = true
        and a.collection = 'arts'
    ),
    bug_evidence as materialized (
      select
        repository_id,
        bug_id,
        'authored_bug_comment' as source,
        art_id as source_id,
        '' as source_url,
        'bug comment' as source_subject,
        body_preview as evidence_preview,
        created_at
      from authored_bug_messages
      union all
      select
        repository_id,
        bug_id,
        'bug_links_to_authored_review' as source,
        change_number as source_id,
        review_url as source_url,
        review_subject as source_subject,
        body_preview as evidence_preview,
        created_at
      from linked_bug_review_messages
      union all
      select
        repository_id,
        bug_id,
        'authored_review_commit_message' as source,
        source_id,
        source_url,
        source_subject,
        source_subject as evidence_preview,
        ''
      from review_bug_refs
      union all
      select
        repository_id,
        bug_id,
        'authored_git_commit_message' as source,
        source_id,
        source_url,
        source_subject,
        source_subject as evidence_preview,
        ''
      from commit_bug_refs
      union all
      select
        repository_id,
        bug_id,
        'authored_art_bug_reference' as source,
        source_id,
        source_url,
        source_subject,
        source_subject as evidence_preview,
        ''
      from authored_art_bug_refs
      where bug_id <> ''
    ),
    bug_rows as materialized (
      select
        br.id as raw_record_id,
        br.doc->>'repository_id' as repository_id,
        repo.repository_name,
        br.doc->'payload'->>'id' as bug_id,
        coalesce(br.doc->'payload'->>'title', br.doc->>'external_id') as title,
        coalesce(br.doc->'payload'->>'web_link', br.doc->>'url', br.doc->>'url') as url,
        coalesce(br.doc->'payload'->>'date_created', '') as created_at,
        coalesce(br.doc->'payload'->>'date_last_updated', '') as updated_at,
        coalesce(br.doc->'payload'->>'date_last_message', '') as last_message_at,
        coalesce(nullif(br.doc->'payload'->>'heat', ''), '0')::bigint as heat,
        coalesce(nullif(br.doc->'payload'->>'message_count', ''), '0')::bigint as message_count,
        case
          when lower(coalesce(br.doc->'payload'->>'security_related', '')) in ('true', 't', '1', 'yes') then true
          else false
        end as security_related,
        coalesce(br.doc->'payload'->'tags', '[]'::jsonb) as tags
      from repointel_records br
      left join repositories repo on repo.repository_id = br.doc->>'repository_id'
      where br.collection = 'raw-records'
        and br.doc->>'record_type' = 'launchpad_bug'
    ),
    bugs as materialized (
      select
        coalesce(br.raw_record_id, '') as raw_record_id,
        coalesce(br.repository_id, be.repository_id) as repository_id,
        coalesce(br.repository_name, repo.repository_name, '') as repository_name,
        be.bug_id,
        coalesce(br.title, 'Launchpad bug ' || be.bug_id) as title,
        coalesce(br.url, 'https://bugs.launchpad.net/bugs/' || be.bug_id) as url,
        coalesce(br.created_at, '') as created_at,
        coalesce(br.updated_at, '') as updated_at,
        coalesce(br.last_message_at, '') as last_message_at,
        coalesce(br.heat, 0)::bigint as heat,
        coalesce(br.message_count, 0)::bigint as message_count,
        coalesce(br.security_related, false) as security_related,
        coalesce(br.tags, '[]'::jsonb) as tags,
        count(*)::bigint as evidence_count,
        jsonb_agg(jsonb_build_object(
          'source', be.source,
          'source_id', be.source_id,
          'source_url', be.source_url,
          'source_subject', be.source_subject,
          'evidence_preview', be.evidence_preview,
          'created_at', be.created_at
        ) order by be.source, be.source_id) as evidence
      from bug_evidence be
      left join bug_rows br
        on br.bug_id = be.bug_id
       and (br.repository_id = be.repository_id or be.repository_id = '')
      left join repositories repo on repo.repository_id = be.repository_id
      group by
        br.raw_record_id,
        coalesce(br.repository_id, be.repository_id),
        coalesce(br.repository_name, repo.repository_name, ''),
        be.bug_id,
        br.title,
        br.url,
        br.created_at,
        br.updated_at,
        br.last_message_at,
        br.heat,
        br.message_count,
        br.security_related,
        br.tags
    ),
    review_bug_counts as materialized (
      select
        repository_id,
        source_id as change_number,
        count(distinct bug_id)::bigint as linked_bug_count
      from bug_evidence
      where source in ('bug_links_to_authored_review', 'authored_review_commit_message')
      group by repository_id, source_id
    ),
    review_history_risk as materialized (
      select
        gr.repository_id,
        gr.change_number,
        least(
          100,
          gr.unresolved_comments * 4
          + round(sqrt(greatest(gr.total_comments, 0)::numeric) * 3)
          + gr.current_revision_number * 3
          + case
              when upper(gr.status) = 'NEW' then least(15, greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp) - 30) / 7)
              else 0
            end
          + coalesce(rbc.linked_bug_count, 0) * 5
        )::bigint as risk_score,
        case
          when least(
            100,
            gr.unresolved_comments * 4
            + round(sqrt(greatest(gr.total_comments, 0)::numeric) * 3)
            + gr.current_revision_number * 3
            + case
                when upper(gr.status) = 'NEW' then least(15, greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp) - 30) / 7)
                else 0
              end
            + coalesce(rbc.linked_bug_count, 0) * 5
          ) >= 70 then 'high'
          when least(
            100,
            gr.unresolved_comments * 4
            + round(sqrt(greatest(gr.total_comments, 0)::numeric) * 3)
            + gr.current_revision_number * 3
            + case
                when upper(gr.status) = 'NEW' then least(15, greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp) - 30) / 7)
                else 0
              end
            + coalesce(rbc.linked_bug_count, 0) * 5
          ) >= 45 then 'elevated'
          when least(
            100,
            gr.unresolved_comments * 4
            + round(sqrt(greatest(gr.total_comments, 0)::numeric) * 3)
            + gr.current_revision_number * 3
            + case
                when upper(gr.status) = 'NEW' then least(15, greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp) - 30) / 7)
                else 0
              end
            + coalesce(rbc.linked_bug_count, 0) * 5
          ) >= 20 then 'watch'
          else 'low'
        end as risk_level,
        jsonb_build_array(
          jsonb_build_object('bucket', 'Unresolved comments', 'value', gr.unresolved_comments, 'points', gr.unresolved_comments * 4),
          jsonb_build_object('bucket', 'Comment volume', 'value', gr.total_comments, 'points', round(sqrt(greatest(gr.total_comments, 0)::numeric) * 3)),
          jsonb_build_object('bucket', 'Patch sets', 'value', gr.current_revision_number, 'points', gr.current_revision_number * 3),
          jsonb_build_object(
            'bucket', 'Open age',
            'value', case when upper(gr.status) = 'NEW' then greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp))::bigint else 0 end,
            'points', case when upper(gr.status) = 'NEW' then least(15, greatest(0, extract(day from now() - nullif(gr.created_at, '')::timestamp) - 30) / 7) else 0 end
          ),
          jsonb_build_object('bucket', 'Linked bugs', 'value', coalesce(rbc.linked_bug_count, 0), 'points', coalesce(rbc.linked_bug_count, 0) * 5)
        ) as contributors
      from gerrit_reviews gr
      left join review_bug_counts rbc
        on rbc.repository_id = gr.repository_id
       and rbc.change_number = gr.change_number
    ),
    repo_line_survival_risk as materialized (
      select
        repository_id,
        count(*)::bigint as line_survival_rows,
        round(avg(coalesce((value->>'line_survival_rate')::numeric, 0)), 4) as avg_line_survival_rate,
        round(max(coalesce((value->>'cross_author_overwrite_rate')::numeric, 0)), 4) as max_cross_author_overwrite_rate,
        least(
          35,
          round((1 - coalesce(avg((value->>'line_survival_rate')::numeric), 0)) * 35)
          + round(coalesce(max((value->>'cross_author_overwrite_rate')::numeric), 0) * 25)
          + round(coalesce(max((value->>'self_rework_rate')::numeric), 0) * 15)
        )::bigint as line_survival_risk_points
      from line_survival
      group by repository_id
    ),
    repo_summary as materialized (
      select
        repo.repository_id,
        repo.repository_name,
        count(distinct ma.id)::bigint as matched_author_count,
        (select count(*)::bigint from gerrit_reviews gr where gr.repository_id = repo.repository_id) as gerrit_reviews_count,
        (select count(*)::bigint from gerrit_reviews gr where gr.repository_id = repo.repository_id and upper(gr.status) = 'MERGED') as merged_reviews_count,
        (select count(*)::bigint from gerrit_reviews gr where gr.repository_id = repo.repository_id and upper(gr.status) = 'NEW') as open_reviews_count,
        (select count(*)::bigint from gerrit_reviews gr where gr.repository_id = repo.repository_id and upper(gr.status) = 'ABANDONED') as abandoned_reviews_count,
        (select count(*)::bigint from git_commits gc where gc.repository_id = repo.repository_id) as git_commits_count,
        (select count(*)::bigint from bugs b where b.repository_id = repo.repository_id) as linked_bugs_count,
        (select count(*)::bigint from authored_bug_messages abm where abm.repository_id = repo.repository_id) as authored_bug_comments_count,
        coalesce((select sum(gc.insertions)::bigint from git_commits gc where gc.repository_id = repo.repository_id), 0) as git_insertions,
        coalesce((select sum(gc.deletions)::bigint from git_commits gc where gc.repository_id = repo.repository_id), 0) as git_deletions
      from repositories repo
      join matched_authors ma on ma.repository_id = repo.repository_id
      group by repo.repository_id, repo.repository_name
    ),
    repo_risk as materialized (
      select
        rs.repository_id,
        rs.repository_name,
        'author_history_risk_v1' as version,
        least(
          100,
          coalesce(max(rhr.risk_score), 0)
          + case
              when rs.git_commits_count = 0 then 25
              when rs.git_commits_count <= 2 then 18
              when rs.git_commits_count <= 4 then 10
              else 0
            end
          + coalesce(max(lsr.line_survival_risk_points), case when rs.git_commits_count > 0 then 15 else 0 end)
          + least(15, rs.linked_bugs_count * 5)
          + least(10, rs.open_reviews_count * 3)
        )::bigint as risk_score,
        case
          when least(
            100,
            coalesce(max(rhr.risk_score), 0)
            + case
                when rs.git_commits_count = 0 then 25
                when rs.git_commits_count <= 2 then 18
                when rs.git_commits_count <= 4 then 10
                else 0
              end
            + coalesce(max(lsr.line_survival_risk_points), case when rs.git_commits_count > 0 then 15 else 0 end)
            + least(15, rs.linked_bugs_count * 5)
            + least(10, rs.open_reviews_count * 3)
          ) >= 70 then 'high'
          when least(
            100,
            coalesce(max(rhr.risk_score), 0)
            + case
                when rs.git_commits_count = 0 then 25
                when rs.git_commits_count <= 2 then 18
                when rs.git_commits_count <= 4 then 10
                else 0
              end
            + coalesce(max(lsr.line_survival_risk_points), case when rs.git_commits_count > 0 then 15 else 0 end)
            + least(15, rs.linked_bugs_count * 5)
            + least(10, rs.open_reviews_count * 3)
          ) >= 45 then 'elevated'
          when least(
            100,
            coalesce(max(rhr.risk_score), 0)
            + case
                when rs.git_commits_count = 0 then 25
                when rs.git_commits_count <= 2 then 18
                when rs.git_commits_count <= 4 then 10
                else 0
              end
            + coalesce(max(lsr.line_survival_risk_points), case when rs.git_commits_count > 0 then 15 else 0 end)
            + least(15, rs.linked_bugs_count * 5)
            + least(10, rs.open_reviews_count * 3)
          ) >= 20 then 'watch'
          else 'low'
        end as risk_level,
        round(coalesce(avg(rhr.risk_score), 0), 1) as avg_review_risk_score,
        coalesce(max(rhr.risk_score), 0)::bigint as max_review_risk_score,
        coalesce(max(lsr.avg_line_survival_rate), null) as avg_line_survival_rate,
        jsonb_build_array(
          jsonb_build_object('bucket', 'Max review risk', 'points', coalesce(max(rhr.risk_score), 0), 'basis', 'review friction, patch sets, age, linked bugs'),
          jsonb_build_object(
            'bucket', 'Sparse git history',
            'points', case
              when rs.git_commits_count = 0 then 25
              when rs.git_commits_count <= 2 then 18
              when rs.git_commits_count <= 4 then 10
              else 0
            end,
            'value', rs.git_commits_count
          ),
          jsonb_build_object(
            'bucket', 'Line survival',
            'points', coalesce(max(lsr.line_survival_risk_points), case when rs.git_commits_count > 0 then 15 else 0 end),
            'line_survival_rate', coalesce(max(lsr.avg_line_survival_rate), null),
            'cross_author_overwrite_rate', coalesce(max(lsr.max_cross_author_overwrite_rate), null)
          ),
          jsonb_build_object('bucket', 'Linked bugs', 'points', least(15, rs.linked_bugs_count * 5), 'value', rs.linked_bugs_count),
          jsonb_build_object('bucket', 'Open reviews', 'points', least(10, rs.open_reviews_count * 3), 'value', rs.open_reviews_count)
        ) as contributors
      from repo_summary rs
      left join review_history_risk rhr on rhr.repository_id = rs.repository_id
      left join repo_line_survival_risk lsr on lsr.repository_id = rs.repository_id
      group by
        rs.repository_id,
        rs.repository_name,
        rs.git_commits_count,
        rs.linked_bugs_count,
        rs.open_reviews_count
    )
    select jsonb_build_object(
      'generated_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      'filters', jsonb_build_object(
        'q', (select q from input),
        'name', (select name from input),
        'last_name', (select last_name from input),
        'email', (select email from input),
        'author_id', (select author_id from input),
        'external_author_id', (select external_author_id from input),
        'gerrit_account_id', (select gerrit_account_id from input),
        'change_number', (select change_number from input),
        'repository_id', (select repository_id from input),
        'project', (select project from input),
        'include_bugs', (select include_bugs from input),
        'limit', ${limit},
        'review_limit', ${reviewLimit},
        'commit_limit', ${commitLimit},
        'bug_limit', ${bugLimit}
      ),
      'identity', jsonb_build_object(
        'matched_authors_count', (select count(*)::bigint from matched_authors),
        'matched_authors', coalesce((
          select jsonb_agg(to_jsonb(rows) order by repository_name, provider, display_name, external_author_id)
          from (
            select
              ma.id,
              ma.repository_id,
              repo.repository_name,
              ma.external_author_id,
              ma.provider,
              ma.display_name,
              ma.email,
              ma.username,
              ma.profile_url,
              ma.match_method
            from matched_authors ma
            left join repositories repo on repo.repository_id = ma.repository_id
            order by repo.repository_name, ma.provider, ma.display_name, ma.external_author_id
            limit ${limit}
          ) rows
        ), '[]'::jsonb)
      ),
      'summary', jsonb_build_object(
        'repositories_count', (select count(distinct repository_id)::bigint from matched_authors),
        'gerrit_reviews_count', (select count(*)::bigint from gerrit_reviews),
        'merged_reviews_count', (select count(*)::bigint from gerrit_reviews where upper(status) = 'MERGED'),
        'open_reviews_count', (select count(*)::bigint from gerrit_reviews where upper(status) = 'NEW'),
        'abandoned_reviews_count', (select count(*)::bigint from gerrit_reviews where upper(status) = 'ABANDONED'),
        'git_commits_count', (select count(*)::bigint from git_commits),
        'git_insertions', coalesce((select sum(insertions)::bigint from git_commits), 0),
        'git_deletions', coalesce((select sum(deletions)::bigint from git_commits), 0),
        'line_survival_summaries_count', (select count(*)::bigint from line_survival),
        'linked_bugs_count', (select count(*)::bigint from bugs),
        'authored_bug_comments_count', (select count(*)::bigint from authored_bug_messages)
      ),
      'risk_summary', jsonb_build_object(
        'version', 'author_history_risk_v1',
        'repositories_scored', (select count(*)::bigint from repo_risk),
        'avg_risk_score', coalesce((select round(avg(risk_score), 1) from repo_risk), 0),
        'max_risk_score', coalesce((select max(risk_score)::bigint from repo_risk), 0),
        'high_repositories', (select count(*)::bigint from repo_risk where risk_level = 'high'),
        'elevated_repositories', (select count(*)::bigint from repo_risk where risk_level in ('high', 'elevated'))
      ),
      'by_repository', coalesce((
        select jsonb_agg(to_jsonb(rows) order by repository_name)
        from (
          select
            rs.*,
            jsonb_build_object(
              'version', rr.version,
              'risk_score', rr.risk_score,
              'risk_level', rr.risk_level,
              'avg_review_risk_score', rr.avg_review_risk_score,
              'max_review_risk_score', rr.max_review_risk_score,
              'avg_line_survival_rate', rr.avg_line_survival_rate,
              'contributors', rr.contributors
            ) as risk
          from repo_summary rs
          left join repo_risk rr on rr.repository_id = rs.repository_id
        ) rows
      ), '[]'::jsonb),
      'repository_analysis', coalesce((
        select jsonb_agg(jsonb_build_object(
          'repository_id', rs.repository_id,
          'repository_name', rs.repository_name,
          'summary', to_jsonb(rs),
          'risk', jsonb_build_object(
            'version', rr.version,
            'risk_score', rr.risk_score,
            'risk_level', rr.risk_level,
            'avg_review_risk_score', rr.avg_review_risk_score,
            'max_review_risk_score', rr.max_review_risk_score,
            'avg_line_survival_rate', rr.avg_line_survival_rate,
            'contributors', rr.contributors
          ),
          'matched_authors', coalesce((
            select jsonb_agg(to_jsonb(rows) order by provider, display_name, external_author_id)
            from (
              select
                ma.id,
                ma.repository_id,
                rs.repository_name,
                ma.external_author_id,
                ma.provider,
                ma.display_name,
                ma.email,
                ma.username,
                ma.profile_url,
                ma.match_method
              from matched_authors ma
              where ma.repository_id = rs.repository_id
            ) rows
          ), '[]'::jsonb),
          'line_survival', coalesce((
            select jsonb_agg(to_jsonb(rows) order by display_name, external_author_id)
            from (
              select
                author_id,
                repository_id,
                repository_name,
                display_name,
                email,
                external_author_id,
                value
              from line_survival ls
              where ls.repository_id = rs.repository_id
            ) rows
          ), '[]'::jsonb),
          'reviews', coalesce((
            select jsonb_agg(to_jsonb(rows) order by coalesce(submitted_at, updated_at, created_at) desc nulls last, change_number desc)
            from (
              select
                raw_record_id,
                repository_id,
                repository_name,
                project,
                branch,
                change_number,
                status,
                subject,
                url,
                owner_account_id,
                owner_name,
                owner_email,
                created_at,
                updated_at,
                submitted_at,
                insertions,
                deletions,
                total_comments,
                unresolved_comments,
                current_revision_number,
                current_revision,
                author_id,
                external_author_id,
                (
                  select jsonb_build_object(
                    'version', 'author_history_review_risk_v1',
                    'risk_score', rhr.risk_score,
                    'risk_level', rhr.risk_level,
                    'contributors', rhr.contributors
                  )
                  from review_history_risk rhr
                  where rhr.repository_id = gr.repository_id
                    and rhr.change_number = gr.change_number
                ) as risk
              from gerrit_reviews gr
              where gr.repository_id = rs.repository_id
            ) rows
          ), '[]'::jsonb),
          'commits', coalesce((
            select jsonb_agg(to_jsonb(rows) order by authored_at desc nulls last, sha)
            from (
              select
                raw_record_id,
                repository_id,
                repository_name,
                sha,
                author_name,
                author_email,
                authored_at,
                subject,
                insertions,
                deletions,
                changed_file_count,
                url
              from git_commits gc
              where gc.repository_id = rs.repository_id
            ) rows
          ), '[]'::jsonb),
          'bugs', coalesce((
            select jsonb_agg(to_jsonb(rows) order by evidence_count desc, heat desc, updated_at desc nulls last, bug_id)
            from (
              select
                raw_record_id,
                repository_id,
                repository_name,
                bug_id,
                title,
                url,
                created_at,
                updated_at,
                last_message_at,
                heat,
                message_count,
                security_related,
                tags,
                evidence_count,
                evidence
              from bugs b
              where b.repository_id = rs.repository_id
            ) rows
          ), '[]'::jsonb)
        ) order by rs.repository_name)
        from repo_summary rs
        left join repo_risk rr on rr.repository_id = rs.repository_id
      ), '[]'::jsonb),
      'line_survival', coalesce((
        select jsonb_agg(to_jsonb(rows) order by repository_name, display_name)
        from (
          select
            author_id,
            repository_id,
            repository_name,
            display_name,
            email,
            external_author_id,
            value
          from line_survival
          order by repository_name, display_name
          limit ${limit}
        ) rows
      ), '[]'::jsonb),
      'reviews', coalesce((
        select jsonb_agg(to_jsonb(rows) order by coalesce(submitted_at, updated_at, created_at) desc nulls last, change_number desc)
        from (
          select
            raw_record_id,
            repository_id,
            repository_name,
            project,
            branch,
            change_number,
            status,
            subject,
            url,
            owner_account_id,
            owner_name,
            owner_email,
            created_at,
            updated_at,
            submitted_at,
            insertions,
            deletions,
            total_comments,
            unresolved_comments,
            current_revision_number,
            current_revision,
            author_id,
            external_author_id,
            (
              select jsonb_build_object(
                'version', 'author_history_review_risk_v1',
                'risk_score', rhr.risk_score,
                'risk_level', rhr.risk_level,
                'contributors', rhr.contributors
              )
              from review_history_risk rhr
              where rhr.repository_id = gerrit_reviews.repository_id
                and rhr.change_number = gerrit_reviews.change_number
            ) as risk
          from gerrit_reviews
          order by coalesce(nullif(submitted_at, ''), nullif(updated_at, ''), nullif(created_at, '')) desc nulls last, change_number desc
          limit ${reviewLimit}
        ) rows
      ), '[]'::jsonb),
      'commits', coalesce((
        select jsonb_agg(to_jsonb(rows) order by repository_name, sha)
        from (
          select
            raw_record_id,
            repository_id,
            repository_name,
            sha,
            author_name,
            author_email,
            authored_at,
            subject,
            insertions,
            deletions,
            changed_file_count,
            url
          from git_commits
          order by repository_name, sha
          limit ${commitLimit}
        ) rows
      ), '[]'::jsonb),
      'bugs', coalesce((
        select jsonb_agg(to_jsonb(rows) order by evidence_count desc, heat desc, updated_at desc nulls last, bug_id)
        from (
          select
            raw_record_id,
            repository_id,
            repository_name,
            bug_id,
            title,
            url,
            created_at,
            updated_at,
            last_message_at,
            heat,
            message_count,
            security_related,
            tags,
            evidence_count,
            evidence
          from bugs
          order by evidence_count desc, heat desc, updated_at desc nulls last, bug_id
          limit ${bugLimit}
        ) rows
      ), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

async function queryRepointelReviewRiskFast(options = {}) {
  const keywordRepositoryId = await resolveKeywordRepositoryId(options);
  const keywordConfig = await getKeywordConfig(keywordRepositoryId);
  const status = String(options.status || "NEW").toUpperCase();
  const normalizedStatus = ["NEW", "MERGED", "ABANDONED", "ALL"].includes(status) ? status : "NEW";
  const dateField = options.dateField === "updated" ? "updated" : "created";
  const monthRange = monthToRange(options.month || "");
  const since = options.since || monthRange.since;
  const until = options.until || monthRange.until;
  const limit = Math.min(2000, Math.max(10, Number(options.limit || 1000)));
  const filters = [
    "collection = 'raw-records'",
    "doc->>'record_type' = 'gerrit_change'",
    "coalesce(doc->'payload'->>'_number', '') <> ''",
  ];
  if (options.repositoryId) {
    filters.push(`doc->>'repository_id' = ${sqlLiteral(options.repositoryId)}`);
  }
  if (options.project) {
    filters.push(`coalesce(nullif(doc->'payload'->>'project', ''), '') = ${sqlLiteral(options.project)}`);
  }
  if (normalizedStatus !== "ALL") {
    filters.push(`upper(coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN')) = ${sqlLiteral(normalizedStatus)}`);
  }
  if (since) {
    filters.push(`nullif(left(coalesce(doc->'payload'->>'${dateField}', ''), 19), '')::timestamp >= ${sqlLiteral(since)}::timestamp`);
  }
  if (until) {
    filters.push(`nullif(left(coalesce(doc->'payload'->>'${dateField}', ''), 19), '')::timestamp < ${sqlLiteral(until)}::timestamp`);
  }
  const historyFilters = [
    "r.collection = 'raw-records'",
    "r.doc->>'record_type' = 'gerrit_change'",
    "coalesce(r.doc->'payload'->'owner'->>'_account_id', '') <> ''",
  ];
  if (options.repositoryId) {
    historyFilters.push(`r.doc->>'repository_id' = ${sqlLiteral(options.repositoryId)}`);
  }
  if (options.project) {
    historyFilters.push(`coalesce(nullif(r.doc->'payload'->>'project', ''), '') = ${sqlLiteral(options.project)}`);
  }

  const changes = await queryJsonArray(`
    select coalesce(jsonb_agg(to_jsonb(rows)), '[]'::jsonb)::text
    from (
      select
        id as raw_record_id,
        doc->>'repository_id' as repository_id,
        doc->'payload'->>'_number' as change_number,
        coalesce(nullif(doc->'payload'->>'project', ''), '') as project,
        coalesce(nullif(doc->'payload'->>'branch', ''), '') as branch,
        coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
        coalesce(nullif(doc->'payload'->>'subject', ''), doc->>'id') as subject,
        coalesce(doc->>'url', '') as review_url,
        coalesce(doc->'payload'->'owner'->>'_account_id', '') as owner_account_id,
        left(coalesce(doc->'payload'->>'created', ''), 19) as created_at,
        left(coalesce(doc->'payload'->>'updated', ''), 19) as updated_at,
        coalesce(nullif(doc->'payload'->>'insertions', ''), '0')::bigint as insertions,
        coalesce(nullif(doc->'payload'->>'deletions', ''), '0')::bigint as deletions,
        coalesce((
          select jsonb_agg(file_row->>'path' order by file_row->>'path')
          from jsonb_array_elements(coalesce(doc->'payload'->'files', '[]'::jsonb)) file_row
          where coalesce(file_row->>'path', '') <> ''
        ), '[]'::jsonb) as changed_files,
        coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
        coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
      from repointel_records
      where ${filters.join("\n        and ")}
      order by nullif(left(coalesce(doc->'payload'->>'${dateField}', ''), 19), '')::timestamp desc nulls last
      limit 5000
    ) rows;
  `);
  if (!changes.length) {
    return reviewRiskResponseSkeleton(options, normalizedStatus, since, until, dateField, limit, keywordRepositoryId, keywordConfig);
  }

  const changeNumbers = uniqueStrings(changes.map((row) => row.change_number));
  const rawRecordIds = uniqueStrings(changes.map((row) => row.raw_record_id));
  const rawRecordToChange = new Map(changes.map((row) => [String(row.raw_record_id), String(row.change_number)]));
  const arts = await queryJsonArray(`
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', id,
      'change_number', doc->>'context_external_id',
      'author_id', coalesce(doc->>'author_id', ''),
      'automated', coalesce(doc->>'automated', 'false'),
      'patch_set', coalesce(nullif(doc->>'patch_set', ''), '0')::bigint,
      'body', coalesce(doc->>'body', '')
    )), '[]'::jsonb)::text
    from repointel_records
    where collection = 'arts'
      and doc->>'type' = 'code_review_message'
      and doc->>'context_external_id' in (${sqlInList(changeNumbers)});
  `);
  const artIds = uniqueStrings(arts.map((art) => art.id));
  const reviewerAuthorIds = uniqueStrings(arts
    .filter((art) => String(art.automated) !== "true")
    .map((art) => art.author_id));
  const ownerExternalIds = uniqueStrings(changes.map((row) => row.owner_account_id ? `gerrit:${row.owner_account_id}` : ""));

  const [artMetadata, rawChangeMetadata, approvalSurvivalMetadata, reviewerSummaryMetadata, ownerLineSurvivalMetadata, ownerReviewHistoryMetadata, authors] = await Promise.all([
    arts.length ? queryJsonArray(`
      with change_rows as materialized (
        select doc->'payload'->>'_number' as change_number
        from repointel_records
        where ${filters.join("\n          and ")}
      ),
      review_arts as materialized (
        select
          a.id,
          a.doc->>'context_external_id' as change_number
        from repointel_records a
        join change_rows c on c.change_number = a.doc->>'context_external_id'
        where a.collection = 'arts'
          and a.doc->>'type' = 'code_review_message'
      )
      select coalesce(jsonb_agg(jsonb_build_object(
        'subject_id', m.doc->>'subject_id',
        'change_number', a.change_number,
        'namespace', m.doc->>'namespace',
        'key', m.doc->>'key',
        'value', m.doc->'value'
      )), '[]'::jsonb)::text
      from review_arts a
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and (
         (m.doc->>'namespace' = 'security.sensitivity' and m.doc->>'key' = 'score')
         or m.doc->>'namespace' = 'security.scenario'
         or (m.doc->>'namespace' = 'review.approval' and m.doc->>'key' = 'vote')
         or (m.doc->>'namespace' = 'review.concern' and m.doc->>'key' = 'signal')
         or m.doc->>'namespace' in ('code.file', 'code.file_role')
       );
    `) : [],
    rawRecordIds.length ? queryJsonArray(`
      select coalesce(jsonb_agg(jsonb_build_object(
        'subject_id', doc->>'subject_id',
        'namespace', doc->>'namespace',
        'key', doc->>'key',
        'value', doc->'value'
      )), '[]'::jsonb)::text
      from repointel_records
      where collection = 'metadata'
        and doc->>'subject_type' = 'raw_record'
        and doc->>'subject_id' in (${sqlInList(rawRecordIds)})
        and (
          doc->>'namespace' = 'security.scenario'
          or doc->>'namespace' = 'security.signal'
          or doc->>'namespace' = 'review.implementation_risk'
          or doc->>'namespace' in ('code.file', 'code.file_role')
        );
    `) : [],
    rawRecordIds.length ? queryJsonArray(`
      select coalesce(jsonb_agg(jsonb_build_object(
        'subject_id', doc->>'subject_id',
        'value', doc->'value'
      )), '[]'::jsonb)::text
      from repointel_records
      where collection = 'metadata'
        and doc->>'subject_type' = 'raw_record'
        and doc->>'subject_id' in (${sqlInList(rawRecordIds)})
        and doc->>'namespace' = 'review.approval_line_survival'
        and doc->>'key' = 'change';
    `) : [],
    reviewerAuthorIds.length ? queryJsonArray(`
      select coalesce(jsonb_agg(jsonb_build_object(
        'subject_id', doc->>'subject_id',
        'value', doc->'value'
      )), '[]'::jsonb)::text
      from repointel_records
      where collection = 'metadata'
        and doc->>'subject_type' = 'author'
        and doc->>'subject_id' in (${sqlInList(reviewerAuthorIds)})
        and doc->>'namespace' = 'review.approval_line_survival'
        and doc->>'key' = 'summary';
    `) : [],
    ownerExternalIds.length ? queryJsonArray(`
      with change_rows as materialized (
        select
          doc->>'repository_id' as repository_id,
          doc->'payload'->>'_number' as change_number,
          coalesce(doc->'payload'->'owner'->>'_account_id', '') as owner_account_id
        from repointel_records
        where ${filters.join("\n          and ")}
      ),
      owner_rows as materialized (
        select
          c.change_number,
          c.repository_id,
          owner_author.id as owner_author_id,
          coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', owner_author.doc->>'email', c.owner_account_id) as owner_name,
          lower(coalesce(owner_author.doc->>'email', '')) as owner_email,
          regexp_replace(lower(coalesce(owner_author.doc->>'username', replace(owner_author.doc->>'external_author_id', 'gerrit:', ''))), '[^a-z0-9]+', '', 'g') as owner_username_key,
          regexp_replace(lower(split_part(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', ''), ' ', 1)), '[^a-z0-9]+', '', 'g') as owner_first_key,
          regexp_replace(lower(regexp_replace(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', ''), '^.*\\s+', '')), '[^a-z0-9]+', '', 'g') as owner_last_key,
          regexp_replace(lower(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', '')), '[^a-z0-9]+', '', 'g') as owner_name_key,
          regexp_replace(lower(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', '')), '[^a-z0-9]+', '.', 'g') as owner_dot_key,
          regexp_replace(lower(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', '')), '[^a-z0-9]+', '', 'g') as owner_flat_key,
          regexp_replace(
            lower(
              left(split_part(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', ''), ' ', 1), 1)
              || regexp_replace(coalesce(owner_author.doc->>'display_name', owner_author.doc->>'name', ''), '^.*\\s+', '')
            ),
            '[^a-z0-9]+',
            '',
            'g'
          ) as owner_first_initial_last_key
        from change_rows c
        join repointel_records owner_author
          on owner_author.collection = 'authors'
         and owner_author.doc->>'external_author_id' = 'gerrit:' || c.owner_account_id
      ),
      git_candidates as materialized (
        select
          git_author.id as git_author_id,
          git_author.doc->>'repository_id' as repository_id,
          coalesce(git_author.doc->>'display_name', git_author.doc->>'name', '') as git_name,
          lower(coalesce(git_author.doc->>'email', replace(git_author.doc->>'external_author_id', 'git:', ''))) as git_email,
          regexp_replace(lower(split_part(coalesce(git_author.doc->>'display_name', git_author.doc->>'name', ''), ' ', 1)), '[^a-z0-9]+', '', 'g') as git_first_key,
          regexp_replace(lower(regexp_replace(coalesce(git_author.doc->>'display_name', git_author.doc->>'name', ''), '^.*\\s+', '')), '[^a-z0-9]+', '', 'g') as git_last_key,
          regexp_replace(lower(coalesce(git_author.doc->>'display_name', git_author.doc->>'name', '')), '[^a-z0-9]+', '', 'g') as git_name_key,
          regexp_replace(lower(split_part(coalesce(git_author.doc->>'email', replace(git_author.doc->>'external_author_id', 'git:', '')), '@', 1)), '[^a-z0-9]+', '.', 'g') as git_dot_key,
          regexp_replace(lower(split_part(coalesce(git_author.doc->>'email', replace(git_author.doc->>'external_author_id', 'git:', '')), '@', 1)), '[^a-z0-9]+', '', 'g') as git_flat_key,
          m.doc->'value' as line_survival,
          coalesce((m.doc->'value'->>'commits_analyzed')::numeric, 0) as commits_analyzed
        from repointel_records git_author
        left join repointel_records m
          on m.collection = 'metadata'
         and m.doc->>'subject_type' = 'author'
         and m.doc->>'subject_id' = git_author.id
         and m.doc->>'namespace' = 'git.line_survival'
         and m.doc->>'key' = 'summary'
        where git_author.collection = 'authors'
          and git_author.doc->>'external_author_id' like 'git:%'
      ),
      candidate_matches as materialized (
        select
          o.*,
          g.git_author_id,
          g.git_email,
          g.git_name,
          g.git_first_key,
          g.git_last_key,
          g.git_name_key,
          g.line_survival,
          g.commits_analyzed,
          case
            when o.owner_email <> '' and g.git_email = o.owner_email then 1
            when o.owner_name_key <> '' and g.git_name_key = o.owner_name_key then 2
            when o.owner_dot_key <> '' and g.git_dot_key = o.owner_dot_key then 3
            when o.owner_flat_key <> '' and g.git_flat_key = o.owner_flat_key then 4
            when o.owner_first_initial_last_key <> '' and g.git_flat_key = o.owner_first_initial_last_key then 5
            when o.owner_first_key = o.owner_last_key and length(o.owner_last_key) >= 4 and o.owner_last_key = g.git_last_key then 6
            when o.owner_first_key = o.owner_last_key and length(o.owner_first_key) >= 4 and o.owner_first_key = g.git_first_key then 7
            else 99
          end as match_rank
        from owner_rows o
        join git_candidates g
          on g.repository_id = o.repository_id
         and (
            (o.owner_email <> '' and g.git_email = o.owner_email)
            or (o.owner_name_key <> '' and g.git_name_key = o.owner_name_key)
            or (o.owner_dot_key <> '' and g.git_dot_key = o.owner_dot_key)
            or (o.owner_flat_key <> '' and g.git_flat_key = o.owner_flat_key)
            or (o.owner_first_initial_last_key <> '' and g.git_flat_key = o.owner_first_initial_last_key)
            or (o.owner_first_key = o.owner_last_key and length(o.owner_last_key) >= 4 and o.owner_last_key = g.git_last_key)
            or (o.owner_first_key = o.owner_last_key and length(o.owner_first_key) >= 4 and o.owner_first_key = g.git_first_key)
          )
      ),
      raw_git_commits as materialized (
        select
          r.doc->>'repository_id' as repository_id,
          coalesce(nullif(r.doc->'payload'->>'sha', ''), r.id) as sha,
          lower(coalesce(r.doc->'payload'->>'author_email', '')) as author_email,
          regexp_replace(lower(split_part(coalesce(r.doc->'payload'->>'author_email', ''), '@', 1)), '[^a-z0-9]+', '', 'g') as author_email_local_key,
          regexp_replace(lower(coalesce(r.doc->'payload'->>'author_name', '')), '[^a-z0-9]+', '', 'g') as author_name_key,
          regexp_replace(lower(split_part(coalesce(r.doc->'payload'->>'author_name', ''), ' ', 1)), '[^a-z0-9]+', '', 'g') as author_first_key,
          coalesce(nullif(r.doc->'payload'->>'insertions', ''), '0')::numeric as insertions,
          coalesce(nullif(r.doc->'payload'->>'deletions', ''), '0')::numeric as deletions
        from repointel_records r
        where r.collection = 'raw-records'
          and r.doc->>'record_type' = 'git_commit'
          and r.doc->>'repository_id' in (select distinct repository_id from owner_rows)
      ),
      git_commit_volume as materialized (
        select
          g.git_author_id,
          count(distinct gc.sha)::numeric as authored_git_commits,
          coalesce(sum(gc.insertions + gc.deletions), 0)::numeric as authored_git_changed_lines
        from (
          select distinct git_author_id, repository_id, git_email, git_name_key
          from candidate_matches
        ) g
        left join raw_git_commits gc
          on gc.repository_id = g.repository_id
         and (
           (g.git_email <> '' and gc.author_email = g.git_email)
           or (g.git_name_key <> '' and gc.author_name_key = g.git_name_key)
         )
        group by g.git_author_id
      ),
      unmatched_owner_rows as materialized (
        select o.*
        from owner_rows o
        where not exists (
          select 1
          from candidate_matches cm
          where cm.change_number = o.change_number
        )
      ),
      owner_git_commit_matches as materialized (
        select o.change_number, gc.sha, gc.insertions, gc.deletions
        from unmatched_owner_rows o
        join raw_git_commits gc
          on gc.repository_id = o.repository_id
         and o.owner_email <> ''
         and gc.author_email = o.owner_email
        union
        select o.change_number, gc.sha, gc.insertions, gc.deletions
        from unmatched_owner_rows o
        join raw_git_commits gc
          on gc.repository_id = o.repository_id
         and o.owner_name_key <> ''
         and gc.author_name_key = o.owner_name_key
        union
        select o.change_number, gc.sha, gc.insertions, gc.deletions
        from unmatched_owner_rows o
        join raw_git_commits gc
          on gc.repository_id = o.repository_id
         and o.owner_username_key <> ''
         and gc.author_email_local_key = o.owner_username_key
        union
        select o.change_number, gc.sha, gc.insertions, gc.deletions
        from unmatched_owner_rows o
        join raw_git_commits gc
          on gc.repository_id = o.repository_id
         and o.owner_first_key = o.owner_last_key
         and length(o.owner_first_key) >= 4
         and gc.author_first_key = o.owner_first_key
      ),
      owner_git_commit_volume as materialized (
        select
          change_number,
          count(distinct sha)::numeric as authored_git_commits,
          coalesce(sum(insertions + deletions), 0)::numeric as authored_git_changed_lines
        from (
          select distinct change_number, sha, insertions, deletions
          from owner_git_commit_matches
        ) matched
        group by change_number
      ),
      ranked_matches as (
        select
          cm.*,
          coalesce(v.authored_git_commits, 0) as authored_git_commits,
          coalesce(v.authored_git_changed_lines, 0) as authored_git_changed_lines,
          row_number() over (
            partition by cm.change_number
            order by
              cm.match_rank,
              cm.commits_analyzed desc,
              cm.git_email
          ) as rn
        from candidate_matches cm
        left join git_commit_volume v on v.git_author_id = cm.git_author_id
      ),
      selected_matches as (
        select *
        from ranked_matches
        where rn = 1
      )
      select coalesce(jsonb_agg(jsonb_build_object(
        'change_number', o.change_number,
        'owner_author_id', o.owner_author_id,
        'owner_git_author_id', coalesce(sm.git_author_id, ''),
        'owner_name', o.owner_name,
        'owner_email', o.owner_email,
        'matched_git_name', coalesce(sm.git_name, ''),
        'matched_git_email', coalesce(sm.git_email, ''),
        'match_rank', coalesce(sm.match_rank, 0),
        'match_method',
          case sm.match_rank
            when 1 then 'exact_email'
            when 2 then 'full_name'
            when 3 then 'full_dot_name_email_localpart'
            when 4 then 'fullname_email_localpart'
            when 5 then 'first_initial_last_email_localpart'
            when 6 then 'last_name'
            when 7 then 'first_name'
            else 'unknown'
          end,
        'authored_git_commits', greatest(coalesce(sm.authored_git_commits, 0), coalesce(ov.authored_git_commits, 0)),
        'authored_git_changed_lines', greatest(coalesce(sm.authored_git_changed_lines, 0), coalesce(ov.authored_git_changed_lines, 0)),
        'value', sm.line_survival
      )), '[]'::jsonb)::text
      from owner_rows o
      left join selected_matches sm on sm.change_number = o.change_number
      left join owner_git_commit_volume ov on ov.change_number = o.change_number;
    `) : [],
    ownerExternalIds.length ? queryJsonArray(`
      with owner_authors as materialized (
        select
          id as owner_author_id,
          doc->>'external_author_id' as external_author_id
        from repointel_records
        where collection = 'authors'
          and doc->>'external_author_id' in (${sqlInList(ownerExternalIds)})
      ),
      owner_changes as materialized (
        select
          r.id as raw_record_id,
          oa.owner_author_id,
          oa.external_author_id,
          coalesce(nullif(r.doc->'payload'->>'status', ''), 'UNKNOWN') as status,
          coalesce(nullif(r.doc->'payload'->>'insertions', ''), '0')::numeric as insertions,
          coalesce(nullif(r.doc->'payload'->>'deletions', ''), '0')::numeric as deletions,
          coalesce(nullif(r.doc->'payload'->>'total_comment_count', ''), '0')::numeric as total_comments,
          coalesce(nullif(r.doc->'payload'->>'unresolved_comment_count', ''), '0')::numeric as unresolved_comments,
          r.doc->'payload'->>'_number' as change_number
        from repointel_records r
        join owner_authors oa
          on oa.external_author_id = 'gerrit:' || coalesce(r.doc->'payload'->'owner'->>'_account_id', '')
        where ${historyFilters.join("\n          and ")}
      ),
      art_stats as materialized (
        select
          oc.raw_record_id,
          max(coalesce(nullif(a.doc->>'patch_set', ''), '0')::numeric) as patch_sets,
          count(*) filter (where coalesce(a.doc->>'automated', 'false') <> 'true')::numeric as human_messages,
          count(distinct a.doc->>'author_id') filter (
            where coalesce(a.doc->>'automated', 'false') <> 'true'
              and coalesce(a.doc->>'author_id', '') <> ''
              and coalesce(a.doc->>'author_id', '') <> oc.owner_author_id
          )::numeric as human_reviewers
        from owner_changes oc
        left join repointel_records a
          on a.collection = 'arts'
         and a.doc->>'type' = 'code_review_message'
         and a.doc->>'context_external_id' = oc.change_number
        group by 1
      ),
      implementation_stats as materialized (
        select
          oc.raw_record_id,
          max(case when m.doc->>'key' = 'implementation_signal_score' then coalesce(nullif(m.doc->>'value', ''), '0')::numeric else 0 end) as implementation_signal_score,
          max(case when m.doc->>'key' = 'concern_message_count' then coalesce(nullif(m.doc->>'value', ''), '0')::numeric else 0 end) as concern_message_count,
          max(case when m.doc->>'key' = 'repeated_concern_file_count' then coalesce(nullif(m.doc->>'value', ''), '0')::numeric else 0 end) as repeated_concern_file_count,
          max(case when m.doc->>'key' = 'security_sensitive_repeated_concern_file_count' then coalesce(nullif(m.doc->>'value', ''), '0')::numeric else 0 end) as security_sensitive_repeated_concern_file_count,
          max(case when m.doc->>'key' = 'small_change_high_friction' and lower(coalesce(m.doc->>'value', 'false')) = 'true' then 1 else 0 end) as small_change_high_friction
        from owner_changes oc
        left join repointel_records m
          on m.collection = 'metadata'
         and m.doc->>'subject_type' = 'raw_record'
         and m.doc->>'subject_id' = oc.raw_record_id
         and m.doc->>'namespace' = 'review.implementation_risk'
        group by 1
      ),
      security_stats as materialized (
        select
          oc.raw_record_id,
          count(*) filter (where m.doc->>'namespace' = 'security.signal')::numeric as security_signal_count,
          count(*) filter (where m.doc->>'namespace' = 'security.scenario')::numeric as security_scenario_count,
          count(*) filter (
            where m.doc->>'namespace' = 'code.file_role'
              and m.doc->'value'->>'role' in ('security_sensitive', 'attack_surface')
          )::numeric as sensitive_file_count
        from owner_changes oc
        left join repointel_records m
          on m.collection = 'metadata'
         and m.doc->>'subject_type' = 'raw_record'
         and m.doc->>'subject_id' = oc.raw_record_id
         and (
           m.doc->>'namespace' in ('security.signal', 'security.scenario')
           or m.doc->>'namespace' = 'code.file_role'
         )
        group by 1
      )
      select coalesce(jsonb_agg(jsonb_build_object(
        'owner_author_id', owner_author_id,
        'external_author_id', external_author_id,
        'authored_reviews_count', authored_reviews_count,
        'merged_reviews_count', merged_reviews_count,
        'abandoned_reviews_count', abandoned_reviews_count,
        'open_reviews_count', open_reviews_count,
        'merged_rate', round(merged_reviews_count / greatest(authored_reviews_count, 1), 4),
        'abandoned_rate', round(abandoned_reviews_count / greatest(authored_reviews_count, 1), 4),
        'avg_changed_lines', round(avg_changed_lines, 1),
        'avg_patch_sets', round(avg_patch_sets, 2),
        'avg_human_messages', round(avg_human_messages, 2),
        'avg_human_reviewers', round(avg_human_reviewers, 2),
        'avg_unresolved_comments', round(avg_unresolved_comments, 2),
        'avg_implementation_signal_score', round(avg_implementation_signal_score, 2),
        'avg_concern_messages', round(avg_concern_messages, 2),
        'high_implementation_reviews', high_implementation_reviews,
        'small_change_high_friction_reviews', small_change_high_friction_reviews,
        'security_experience_reviews', security_experience_reviews,
        'sensitive_file_reviews', sensitive_file_reviews
      ) order by owner_author_id), '[]'::jsonb)::text
      from (
        select
          oc.owner_author_id,
          oc.external_author_id,
          count(*)::numeric as authored_reviews_count,
          count(*) filter (where upper(oc.status) = 'MERGED')::numeric as merged_reviews_count,
          count(*) filter (where upper(oc.status) = 'ABANDONED')::numeric as abandoned_reviews_count,
          count(*) filter (where upper(oc.status) = 'NEW')::numeric as open_reviews_count,
          avg(oc.insertions + oc.deletions) as avg_changed_lines,
          avg(coalesce(a.patch_sets, 0)) as avg_patch_sets,
          avg(coalesce(a.human_messages, 0)) as avg_human_messages,
          avg(coalesce(a.human_reviewers, 0)) as avg_human_reviewers,
          avg(oc.unresolved_comments) as avg_unresolved_comments,
          avg(coalesce(i.implementation_signal_score, 0)) as avg_implementation_signal_score,
          avg(coalesce(i.concern_message_count, 0)) as avg_concern_messages,
          count(*) filter (where coalesce(i.implementation_signal_score, 0) >= 100)::numeric as high_implementation_reviews,
          count(*) filter (where coalesce(i.small_change_high_friction, 0) > 0)::numeric as small_change_high_friction_reviews,
          count(*) filter (
            where coalesce(s.security_signal_count, 0) > 0
               or coalesce(s.security_scenario_count, 0) > 0
          )::numeric as security_experience_reviews,
          count(*) filter (where coalesce(s.sensitive_file_count, 0) > 0)::numeric as sensitive_file_reviews
        from owner_changes oc
        left join art_stats a on a.raw_record_id = oc.raw_record_id
        left join implementation_stats i on i.raw_record_id = oc.raw_record_id
        left join security_stats s on s.raw_record_id = oc.raw_record_id
        group by 1, 2
      ) rows;
    `) : [],
    (reviewerAuthorIds.length || ownerExternalIds.length) ? queryJsonArray(`
      select coalesce(jsonb_agg(jsonb_build_object(
        'id', id,
        'display_name', coalesce(doc->>'display_name', doc->>'name', doc->>'email', doc->>'username', id),
        'external_author_id', coalesce(doc->>'external_author_id', '')
      )), '[]'::jsonb)::text
      from repointel_records
      where collection = 'authors'
        and (
          id in (${sqlInList(reviewerAuthorIds.length ? reviewerAuthorIds : [""])})
          or doc->>'external_author_id' in (${sqlInList(ownerExternalIds.length ? ownerExternalIds : [""])})
        );
    `) : [],
  ]);

  const authorsById = new Map(authors.map((author) => [String(author.id), author]));
  const authorsByExternalId = new Map(authors.map((author) => [String(author.external_author_id), author]));
  const artChange = new Map(arts.map((art) => [String(art.id), String(art.change_number)]));
  const stats = new Map(changes.map((change) => [String(change.change_number), emptyReviewRiskStats()]));
  const participantSets = new Map(changes.map((change) => [String(change.change_number), new Set()]));
  const compiledKeywordRules = compileKeywordRules(keywordConfig.rules);
  const ownerAuthorIdsByChange = new Map(changes.map((change) => {
    const ownerRecord = authorsByExternalId.get(`gerrit:${change.owner_account_id}`);
    return [String(change.change_number || ""), ownerRecord?.id || ""];
  }));

  for (const art of arts) {
    const changeNumber = String(art.change_number || "");
    const rowStats = stats.get(changeNumber);
    if (!rowStats) continue;
    const automated = String(art.automated || "false") === "true";
    const authorId = String(art.author_id || "");
    rowStats.review_messages += 1;
    rowStats.patch_sets = Math.max(rowStats.patch_sets, numberValue(art.patch_set));
    if (automated) {
      rowStats.automated_messages += 1;
      continue;
    }
    rowStats.human_messages += 1;
    if (authorId) {
      participantSets.get(changeNumber)?.add(authorId);
    }
    const body = String(art.body || "");
    for (const rule of compiledKeywordRules) {
      if (!rule.regex.test(body)) continue;
      rowStats.security_signal_mentions += 1;
      rowStats.keyword_weighted_score += numberValue(rule.weight);
      rowStats.keywordKindIds.add(rule.id);
      rowStats.keyword_hits.push({
        id: rule.id,
        label: rule.label,
        color: rule.color,
        weight: rule.weight,
        order: rule.order,
      });
    }
  }

  for (const metadata of artMetadata) {
    const changeNumber = String(metadata.change_number || "") || artChange.get(String(metadata.subject_id || ""));
    const rowStats = stats.get(changeNumber);
    if (rowStats) {
      applyReviewRiskMetadata(rowStats, metadata, {
        ownerAuthorId: ownerAuthorIdsByChange.get(changeNumber) || "",
      });
    }
  }
  for (const metadata of rawChangeMetadata) {
    const changeNumber = rawRecordToChange.get(String(metadata.subject_id || ""));
    const rowStats = stats.get(changeNumber);
    if (rowStats) applyReviewRiskMetadata(rowStats, metadata);
  }
  for (const metadata of approvalSurvivalMetadata) {
    const changeNumber = rawRecordToChange.get(String(metadata.subject_id || ""));
    const rowStats = stats.get(changeNumber);
    if (rowStats) applyApprovalSurvival(rowStats, metadata.value || {});
  }
  const reviewerSummaryByAuthor = new Map(reviewerSummaryMetadata.map((metadata) => [String(metadata.subject_id), metadata.value || {}]));
  const ownerReviewHistoryByAuthor = new Map(ownerReviewHistoryMetadata.map((metadata) => [String(metadata.owner_author_id || ""), metadata]));
  const ownerReviewHistoryByExternal = new Map(ownerReviewHistoryMetadata.map((metadata) => [String(metadata.external_author_id || ""), metadata]));
  const ownerLineSurvivalByChange = new Map(ownerLineSurvivalMetadata.map((metadata) => [
    String(metadata.change_number),
    {
      owner_author_id: String(metadata.owner_author_id || ""),
      owner_git_author_id: String(metadata.owner_git_author_id || ""),
      owner_name: String(metadata.owner_name || ""),
      owner_email: String(metadata.owner_email || ""),
      matched_git_name: String(metadata.matched_git_name || ""),
      matched_git_email: String(metadata.matched_git_email || ""),
      match_method: String(metadata.match_method || ""),
      match_rank: numberValue(metadata.match_rank),
      authored_git_commits: numberValue(metadata.authored_git_commits),
      authored_git_changed_lines: numberValue(metadata.authored_git_changed_lines),
      summary: metadata.value || {},
    },
  ]));

  const finalRows = changes.map((change) => {
    const changeNumber = String(change.change_number || "");
    const rowStats = stats.get(changeNumber) || emptyReviewRiskStats();
    const ownerRecord = authorsByExternalId.get(`gerrit:${change.owner_account_id}`);
    const ownerAuthorId = ownerRecord?.id || "";
    const participantIds = Array.from(participantSets.get(changeNumber) || [])
      .filter((authorId) => !ownerAuthorId || authorId !== ownerAuthorId);
    const reviewerNames = participantIds.map((authorId) => displayAuthorName(authorsById, authorId));
    const reviewerHistory = participantIds
      .map((authorId) => ({ authorId, summary: reviewerSummaryByAuthor.get(authorId) }))
      .filter((entry) => entry.summary)
      .map((entry) => ({
        reviewer: displayAuthorName(authorsById, entry.authorId),
        reviewer_author_id: entry.authorId,
        line_survival_rate: numberValue(entry.summary.line_survival_rate),
        reviewed_changes_count: numberValue(entry.summary.reviewed_changes_count),
        approvals_count: numberValue(entry.summary.approvals_count),
        insertions_tracked: numberValue(entry.summary.insertions_tracked),
        surviving_lines: numberValue(entry.summary.surviving_lines),
      }))
      .sort((left, right) => left.line_survival_rate - right.line_survival_rate || left.reviewer.localeCompare(right.reviewer));
    const owner = ownerRecord?.display_name || change.owner_account_id || "";
    const authorCompetence = ownerLineSurvivalByChange.get(changeNumber) || {
      owner_author_id: ownerRecord?.id || "",
      owner_git_author_id: "",
      owner_name: owner,
      owner_email: "",
      matched_git_name: "",
      matched_git_email: "",
      match_method: "",
      match_rank: 0,
      summary: null,
    };
    authorCompetence.review_history = ownerReviewHistoryByAuthor.get(ownerAuthorId)
      || ownerReviewHistoryByExternal.get(`gerrit:${change.owner_account_id}`)
      || null;
    return scoreReviewRiskRow(change, rowStats, participantIds, reviewerNames, reviewerHistory, owner, authorCompetence);
  }).sort((left, right) =>
    right.priority_rank - left.priority_rank
    || right.deep_review_priority_score - left.deep_review_priority_score
    || right.implementation_score - left.implementation_score
    || right.author_score - left.author_score
    || right.security_score - left.security_score
    || right.flat_risk_score - left.flat_risk_score
    || right.friction_score - left.friction_score
  );
  const scoreRows = finalRows.map((row) => row.deep_review_priority_score || row.risk_score || 0);
  const flatScoreRows = finalRows.map((row) => row.flat_risk_score || 0);
  const bucketScoreRows = finalRows.map((row) => row.bucket_score || 0);

  return {
    generated_at: new Date().toISOString(),
    filters: {
      repository_id: options.repositoryId || "",
      project: options.project || "",
      status: normalizedStatus,
      month: options.month || "",
      since: since || "",
      until: until || "",
      date_field: dateField,
      limit,
      keyword_repository_id: keywordRepositoryId,
    },
    keyword_config: keywordConfig,
    review_risk_weights: reviewRiskWeights(),
    review_risk_summary: {
      proposed_reviews: finalRows.length,
      critical_reviews: finalRows.filter((row) => row.risk_level === "critical").length,
      high_reviews: finalRows.filter((row) => row.risk_level === "critical" || row.risk_level === "high").length,
      urgent_reviews: finalRows.filter((row) => row.priority_lane === "urgent_compute").length,
      high_compute_reviews: finalRows.filter((row) => row.priority_lane === "urgent_compute" || row.priority_lane === "high_compute").length,
      avg_risk_score: roundNumber(average(scoreRows), 1),
      max_risk_score: Math.max(0, ...scoreRows),
      avg_flat_risk_score: roundNumber(average(flatScoreRows), 1),
      max_flat_risk_score: Math.max(0, ...flatScoreRows),
      avg_bucket_score: roundNumber(average(bucketScoreRows), 1),
      max_bucket_score: Math.max(0, ...bucketScoreRows),
    },
    proposed_review_risk: finalRows.slice(0, limit),
  };
}

async function queryRepointelReviewRisk(options = {}) {
  return queryRepointelReviewRiskFast(options);

  const keywordRepositoryId = await resolveKeywordRepositoryId(options);
  const keywordConfig = await getKeywordConfig(keywordRepositoryId);
  const keywordRulesSql = keywordRulesValuesSql(keywordConfig.rules);
  const status = String(options.status || "NEW").toUpperCase();
  const normalizedStatus = ["NEW", "MERGED", "ABANDONED", "ALL"].includes(status) ? status : "NEW";
  const dateField = options.dateField === "updated" ? "updated" : "created";
  const monthRange = monthToRange(options.month || "");
  const since = options.since || monthRange.since;
  const until = options.until || monthRange.until;
  const limit = Math.min(500, Math.max(10, Number(options.limit || 100)));
  const filters = [
    "collection = 'raw-records'",
    "doc->>'record_type' = 'gerrit_change'",
    "coalesce(doc->'payload'->>'_number', '') <> ''",
  ];
  if (options.repositoryId) {
    filters.push(`doc->>'repository_id' = ${sqlLiteral(options.repositoryId)}`);
  }
  if (options.project) {
    filters.push(`coalesce(nullif(doc->'payload'->>'project', ''), '') = ${sqlLiteral(options.project)}`);
  }
  if (normalizedStatus !== "ALL") {
    filters.push(`upper(coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN')) = ${sqlLiteral(normalizedStatus)}`);
  }
  if (since) {
    filters.push(`nullif(left(coalesce(doc->'payload'->>'${dateField}', ''), 19), '')::timestamp >= ${sqlLiteral(since)}::timestamp`);
  }
  if (until) {
    filters.push(`nullif(left(coalesce(doc->'payload'->>'${dateField}', ''), 19), '')::timestamp < ${sqlLiteral(until)}::timestamp`);
  }
  const sql = `
    with
    keyword_rules(id, label, pattern, color, weight, display_order, enabled) as (
      ${keywordRulesSql}
    ),
    change_rows as materialized (
      select
        id as raw_record_id,
        doc->>'repository_id' as repository_id,
        doc->'payload'->>'_number' as change_number,
        coalesce(nullif(doc->'payload'->>'project', ''), '') as project,
        coalesce(nullif(doc->'payload'->>'branch', ''), '') as branch,
        coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN') as status,
        coalesce(nullif(doc->'payload'->>'subject', ''), doc->>'id') as subject,
        coalesce(doc->>'url', '') as review_url,
        coalesce(doc->'payload'->'owner'->>'_account_id', '') as owner_account_id,
        left(coalesce(doc->'payload'->>'created', ''), 19) as created_at,
        left(coalesce(doc->'payload'->>'updated', ''), 19) as updated_at,
        coalesce(nullif(doc->'payload'->>'insertions', ''), '0')::bigint as insertions,
        coalesce(nullif(doc->'payload'->>'deletions', ''), '0')::bigint as deletions,
        coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::bigint as total_comments,
        coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::bigint as unresolved_comments
      from repointel_records
      where ${filters.join("\n        and ")}
    ),
    review_arts as materialized (
      select
        a.id,
        a.doc,
        a.doc->>'context_external_id' as change_number
      from repointel_records a
      join change_rows c on c.change_number = a.doc->>'context_external_id'
      where a.collection = 'arts'
        and a.doc->>'type' = 'code_review_message'
    ),
    review_participants as materialized (
      select distinct
        change_number,
        doc->>'author_id' as reviewer_author_id
      from review_arts
      where coalesce(doc->>'automated', 'false') <> 'true'
        and coalesce(doc->>'author_id', '') <> ''
    ),
    art_stats as (
      select
        a.change_number,
        count(*)::bigint as review_messages,
        count(*) filter (where coalesce(a.doc->>'automated', 'false') <> 'true')::bigint as human_messages,
        count(*) filter (where coalesce(a.doc->>'automated', 'false') = 'true')::bigint as automated_messages,
        max(coalesce(nullif(a.doc->>'patch_set', ''), '0')::bigint) as patch_sets,
        count(distinct nullif(a.doc->>'author_id', '')) filter (
          where coalesce(a.doc->>'automated', 'false') <> 'true'
        )::bigint as human_reviewers,
        coalesce(jsonb_agg(distinct a.doc->>'author_id') filter (
          where coalesce(a.doc->>'automated', 'false') <> 'true'
            and coalesce(a.doc->>'author_id', '') <> ''
        ), '[]'::jsonb) as reviewer_author_ids,
        left(string_agg(distinct coalesce(au.doc->>'display_name', a.doc->>'author_id'), ', ') filter (
          where coalesce(a.doc->>'automated', 'false') <> 'true'
        ), 180) as reviewers
      from review_arts a
      left join repointel_records au on au.collection = 'authors' and au.id = a.doc->>'author_id'
      group by 1
    ),
    vote_stats as (
      select
        a.change_number,
        count(*) filter (where m.doc->'value'->>'action' = 'vote')::bigint as vote_events,
        count(*) filter (
          where m.doc->'value'->>'action' = 'vote'
            and coalesce((m.doc->'value'->>'value')::int, 0) > 0
        )::bigint as positive_votes,
        count(*) filter (
          where m.doc->'value'->>'action' = 'vote'
            and coalesce((m.doc->'value'->>'value')::int, 0) < 0
        )::bigint as negative_votes
      from review_arts a
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' = 'review.approval'
       and m.doc->>'key' = 'vote'
      group by 1
    ),
    approval_change_survival as (
      select
        c.change_number,
        count(*)::bigint as approval_survival_approvals,
        round(avg(coalesce((m.doc->'value'->>'line_survival_rate')::numeric, 0)), 4) as approval_line_survival_rate,
        min(coalesce((m.doc->'value'->>'line_survival_rate')::numeric, 0)) as min_approval_line_survival_rate,
        sum(coalesce((m.doc->'value'->>'commit_insertions_tracked')::bigint, 0))::bigint as approval_insertions_tracked,
        sum(coalesce((m.doc->'value'->>'surviving_lines')::bigint, 0))::bigint as approval_surviving_lines,
        sum(coalesce((m.doc->'value'->>'cross_author_overwritten_lines')::bigint, 0))::bigint as approval_cross_author_overwritten_lines,
        coalesce(jsonb_agg(jsonb_build_object(
          'reviewer', m.doc->'value'->>'reviewer_key',
          'reviewer_author_id', m.doc->'value'->>'reviewer_author_id',
          'line_survival_rate', coalesce((m.doc->'value'->>'line_survival_rate')::numeric, 0),
          'insertions_tracked', coalesce((m.doc->'value'->>'commit_insertions_tracked')::bigint, 0),
          'surviving_lines', coalesce((m.doc->'value'->>'surviving_lines')::bigint, 0),
          'cross_author_overwritten_lines', coalesce((m.doc->'value'->>'cross_author_overwritten_lines')::bigint, 0),
          'labels', coalesce(m.doc->'value'->'labels', '[]'::jsonb)
        ) order by coalesce((m.doc->'value'->>'line_survival_rate')::numeric, 0), m.doc->'value'->>'reviewer_key'), '[]'::jsonb) as approval_survival_reviewers
      from change_rows c
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'raw_record'
       and m.doc->>'subject_id' = c.raw_record_id
       and m.doc->>'namespace' = 'review.approval_line_survival'
       and m.doc->>'key' = 'change'
      group by 1
    ),
    reviewer_history_survival_rows as (
      select distinct
        p.change_number,
        p.reviewer_author_id,
        coalesce(au.doc->>'display_name', au.doc->>'email', au.doc->>'username', p.reviewer_author_id) as reviewer,
        m.doc as metadata_doc
      from review_participants p
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'author'
       and m.doc->>'subject_id' = p.reviewer_author_id
       and m.doc->>'namespace' = 'review.approval_line_survival'
       and m.doc->>'key' = 'summary'
      left join repointel_records au
        on au.collection = 'authors'
       and au.id = p.reviewer_author_id
    ),
    reviewer_history_survival as (
      select
        change_number,
        count(*)::bigint as reviewer_history_count,
        round(avg(coalesce((metadata_doc->'value'->>'line_survival_rate')::numeric, 0)), 4) as reviewer_avg_line_survival_rate,
        min(coalesce((metadata_doc->'value'->>'line_survival_rate')::numeric, 0)) as reviewer_min_line_survival_rate,
        sum(coalesce((metadata_doc->'value'->>'reviewed_changes_count')::bigint, 0))::bigint as reviewer_history_changes,
        coalesce(jsonb_agg(jsonb_build_object(
          'reviewer', reviewer,
          'reviewer_author_id', reviewer_author_id,
          'line_survival_rate', coalesce((metadata_doc->'value'->>'line_survival_rate')::numeric, 0),
          'reviewed_changes_count', coalesce((metadata_doc->'value'->>'reviewed_changes_count')::bigint, 0),
          'approvals_count', coalesce((metadata_doc->'value'->>'approvals_count')::bigint, 0),
          'insertions_tracked', coalesce((metadata_doc->'value'->>'insertions_tracked')::bigint, 0),
          'surviving_lines', coalesce((metadata_doc->'value'->>'surviving_lines')::bigint, 0)
        ) order by coalesce((metadata_doc->'value'->>'line_survival_rate')::numeric, 0), reviewer), '[]'::jsonb) as reviewer_history
      from reviewer_history_survival_rows
      group by 1
    ),
    scenario_stats as (
      select
        a.change_number,
        count(*)::bigint as security_scenario_hits
      from review_arts a
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' = 'security.scenario'
      group by 1
    ),
    keyword_hits as (
      select
        a.change_number,
        a.id as art_id,
        kr.id as keyword_id,
        kr.label,
        kr.color,
        kr.weight,
        kr.display_order
      from review_arts a
      join keyword_rules kr
        on kr.enabled = true
       and coalesce(a.doc->>'body', '') ~* kr.pattern
      where coalesce(a.doc->>'automated', 'false') <> 'true'
    ),
    keyword_stats as (
      select
        change_number,
        count(*)::bigint as security_signal_mentions,
        count(distinct keyword_id)::bigint as distinct_signal_kinds,
        sum(weight)::bigint as keyword_weighted_score,
        coalesce(jsonb_agg(
          jsonb_build_object(
            'id', keyword_id,
            'label', label,
            'color', color,
            'weight', weight,
            'order', display_order
          )
          order by display_order, label
        ), '[]'::jsonb) as keyword_hits
      from keyword_hits
      group by 1
    ),
    sensitivity_stats as (
      select
        a.change_number,
        round(max((m.doc->'value'->>'score')::numeric), 2) as max_sensitivity_score,
        round(avg((m.doc->'value'->>'score')::numeric), 2) as avg_sensitivity_score,
        count(*) filter (where (m.doc->'value'->>'score')::numeric >= 40)::bigint as sensitivity_ge40_messages,
        count(*) filter (where (m.doc->'value'->>'score')::numeric >= 55)::bigint as sensitivity_ge55_messages,
        count(*) filter (where (m.doc->'value'->>'score')::numeric >= 70)::bigint as sensitivity_ge70_messages,
        sum(case
          when (m.doc->'value'->>'score')::numeric >= 70 then 30
          when (m.doc->'value'->>'score')::numeric >= 55 then 14
          when (m.doc->'value'->>'score')::numeric >= 40 then 6
          else 0
        end)::bigint as sensitivity_weighted_score
      from review_arts a
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' = 'security.sensitivity'
       and m.doc->>'key' = 'score'
      group by 1
    ),
    file_stats as (
      select
        a.change_number,
        count(distinct case
          when m.doc->>'namespace' = 'code.file'
           and m.doc->>'key' = 'path'
           and m.doc->>'value' not ilike '%PATCHSET_LEVEL%'
          then m.doc->>'value'
        end)::bigint as touched_files,
        count(distinct case
          when m.doc->>'namespace' = 'code.file_role'
           and m.doc->'value'->>'role' = 'security_sensitive'
          then m.doc->'value'->>'path'
        end)::bigint as security_sensitive_files,
        count(distinct case
          when m.doc->>'namespace' = 'code.file_role'
           and m.doc->'value'->>'role' = 'attack_surface'
          then m.doc->'value'->>'path'
        end)::bigint as attack_surface_files,
        count(distinct case
          when (
            m.doc->>'namespace' = 'code.file_role'
            and m.doc->'value'->>'role' = 'dependency_manifest'
          ) or (
            m.doc->>'namespace' = 'code.file'
            and m.doc->>'key' = 'path'
            and (
              m.doc->>'value' ilike '%requirements%'
              or m.doc->>'value' ilike '%package.json%'
              or m.doc->>'value' ilike '%setup.py%'
              or m.doc->>'value' ilike '%setup.cfg%'
              or m.doc->>'value' ilike '%pyproject.toml%'
              or m.doc->>'value' ilike '%tox.ini%'
            )
          )
          then coalesce(m.doc->'value'->>'path', m.doc->>'value')
        end)::bigint as dependency_files,
        count(distinct case
          when (
            m.doc->>'namespace' = 'code.file_role'
            and m.doc->'value'->>'role' = 'cicd_workflow'
          ) or (
            m.doc->>'namespace' = 'code.file'
            and m.doc->>'key' = 'path'
            and (
              m.doc->>'value' ilike '%.github/workflows%'
              or m.doc->>'value' ilike '%zuul%'
              or m.doc->>'value' ilike '%jenkins%'
              or m.doc->>'value' ilike '%tox.ini%'
            )
          )
          then coalesce(m.doc->'value'->>'path', m.doc->>'value')
        end)::bigint as workflow_files
      from review_arts a
      join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' in ('code.file', 'code.file_role')
      group by 1
    ),
    joined as (
      select
        c.*,
        coalesce(o.doc->>'display_name', c.owner_account_id) as owner,
        coalesce(a.review_messages, 0) as review_messages,
        coalesce(a.human_messages, 0) as human_messages,
        coalesce(a.automated_messages, 0) as automated_messages,
        coalesce(a.patch_sets, 0) as patch_sets,
        coalesce(a.human_reviewers, 0) as human_reviewers,
        coalesce(a.reviewer_author_ids, '[]'::jsonb) as reviewer_author_ids,
        coalesce(a.reviewers, '') as reviewers,
        coalesce(acs.approval_survival_approvals, 0) as approval_survival_approvals,
        coalesce(acs.approval_line_survival_rate, 0) as approval_line_survival_rate,
        coalesce(acs.min_approval_line_survival_rate, 0) as min_approval_line_survival_rate,
        coalesce(acs.approval_insertions_tracked, 0) as approval_insertions_tracked,
        coalesce(acs.approval_surviving_lines, 0) as approval_surviving_lines,
        coalesce(acs.approval_cross_author_overwritten_lines, 0) as approval_cross_author_overwritten_lines,
        coalesce(acs.approval_survival_reviewers, '[]'::jsonb) as approval_survival_reviewers,
        coalesce(rhs.reviewer_history_count, 0) as reviewer_history_count,
        coalesce(rhs.reviewer_avg_line_survival_rate, 0) as reviewer_avg_line_survival_rate,
        coalesce(rhs.reviewer_min_line_survival_rate, 0) as reviewer_min_line_survival_rate,
        coalesce(rhs.reviewer_history_changes, 0) as reviewer_history_changes,
        coalesce(rhs.reviewer_history, '[]'::jsonb) as reviewer_history,
        coalesce(v.vote_events, 0) as vote_events,
        coalesce(v.positive_votes, 0) as positive_votes,
        coalesce(v.negative_votes, 0) as negative_votes,
        coalesce(k.security_signal_mentions, 0) as security_signal_mentions,
        coalesce(k.distinct_signal_kinds, 0) as distinct_signal_kinds,
        coalesce(k.keyword_weighted_score, 0) as keyword_weighted_score,
        coalesce(k.keyword_hits, '[]'::jsonb) as keyword_hits,
        coalesce(sc.security_scenario_hits, 0) as security_scenario_hits,
        coalesce(ss.max_sensitivity_score, 0) as max_sensitivity_score,
        coalesce(ss.avg_sensitivity_score, 0) as avg_sensitivity_score,
        coalesce(ss.sensitivity_ge40_messages, 0) as sensitivity_ge40_messages,
        coalesce(ss.sensitivity_ge55_messages, 0) as sensitivity_ge55_messages,
        coalesce(ss.sensitivity_ge70_messages, 0) as sensitivity_ge70_messages,
        coalesce(ss.sensitivity_weighted_score, 0) as sensitivity_weighted_score,
        coalesce(f.touched_files, 0) as touched_files,
        coalesce(f.security_sensitive_files, 0) as security_sensitive_files,
        coalesce(f.attack_surface_files, 0) as attack_surface_files,
        coalesce(f.dependency_files, 0) as dependency_files,
        coalesce(f.workflow_files, 0) as workflow_files,
        greatest(0, extract(day from now() - nullif(c.created_at, '')::timestamp))::bigint as age_days
      from change_rows c
      left join art_stats a on a.change_number = c.change_number
      left join approval_change_survival acs on acs.change_number = c.change_number
      left join reviewer_history_survival rhs on rhs.change_number = c.change_number
      left join vote_stats v on v.change_number = c.change_number
      left join keyword_stats k on k.change_number = c.change_number
      left join scenario_stats sc on sc.change_number = c.change_number
      left join sensitivity_stats ss on ss.change_number = c.change_number
      left join file_stats f on f.change_number = c.change_number
      left join repointel_records o
        on o.collection = 'authors'
       and o.doc->>'external_author_id' = 'gerrit:' || c.owner_account_id
    ),
    scored as (
      select
        *,
        least(
          240,
          least(keyword_weighted_score, ${keywordScoreCap})
          + distinct_signal_kinds * 6
          + security_scenario_hits * 2
          + sensitivity_weighted_score
          + security_sensitive_files * 22
          + attack_surface_files * 16
          + dependency_files * 12
          + workflow_files * 12
        )::bigint as security_score,
        least(
          180,
          unresolved_comments * 12
          + negative_votes * 18
          + least(positive_votes, negative_votes) * 28
          + round(sqrt(greatest(total_comments, 0)::numeric) * 7)
        )::bigint as friction_score,
        least(
          160,
          patch_sets * 5
          + touched_files * 3
          + round(sqrt(greatest(insertions + deletions, 0)::numeric) * 4)
          + human_reviewers * 6
        )::bigint as rework_score,
        case
          when status = 'NEW' then least(50, greatest(age_days - 30, 0) / 14)::bigint
          else 0
        end as stale_score,
        least(
          120,
          case
            when approval_survival_approvals > 0 then
              round((1 - approval_line_survival_rate) * 90)
              + least(30, approval_cross_author_overwritten_lines * 3)
            when reviewer_history_count > 0 then
              round((1 - reviewer_avg_line_survival_rate) * 80)
              + least(30, greatest(0, 3 - reviewer_history_count) * 8)
            else 0
          end
        )::bigint as reviewer_score
      from joined
    ),
    final_rows as materialized (
      select
        *,
        (security_score + friction_score + rework_score + stale_score + reviewer_score)::bigint as risk_score,
        case
          when security_score + friction_score + rework_score + stale_score + reviewer_score >= 360 then 'critical'
          when security_score + friction_score + rework_score + stale_score + reviewer_score >= 260 then 'high'
          when security_score + friction_score + rework_score + stale_score + reviewer_score >= 160 then 'elevated'
          else 'watch'
        end as risk_level,
        array_remove(array[
          case when sensitivity_ge40_messages > 0 then sensitivity_ge40_messages || ' ONNX >=40' end,
          case when sensitivity_ge55_messages > 0 then sensitivity_ge55_messages || ' ONNX >=55' end,
          case when sensitivity_ge70_messages > 0 then sensitivity_ge70_messages || ' ONNX >=70' end,
          case when security_signal_mentions > 0 then security_signal_mentions || ' rule keyword hits' end,
          case when security_sensitive_files > 0 then security_sensitive_files || ' security-sensitive files' end,
          case when attack_surface_files > 0 then attack_surface_files || ' attack-surface files' end,
          case when dependency_files > 0 then dependency_files || ' dependency files' end,
          case when workflow_files > 0 then workflow_files || ' workflow/CI files' end,
          case when unresolved_comments > 0 then unresolved_comments || ' unresolved comments' end,
          case when negative_votes > 0 then negative_votes || ' negative votes' end,
          case when patch_sets > 8 then patch_sets || ' patch sets' end,
          case when approval_survival_approvals > 0 then approval_survival_approvals || ' approval survival rows, avg ' || round(approval_line_survival_rate * 100, 1) || '%' end,
          case when approval_survival_approvals = 0 and reviewer_history_count > 0 then reviewer_history_count || ' reviewer history rows, avg ' || round(reviewer_avg_line_survival_rate * 100, 1) || '%' end,
          case when age_days > 120 then age_days || ' days open' end
        ], null) as risk_reasons,
        jsonb_build_array(
          jsonb_build_object(
            'bucket', 'Security',
            'points', security_score,
            'items', jsonb_build_array(
              jsonb_build_object('label', 'Keyword score', 'value', keyword_weighted_score, 'points', least(keyword_weighted_score, ${keywordScoreCap})),
              jsonb_build_object('label', 'Keyword kinds', 'value', distinct_signal_kinds, 'points', distinct_signal_kinds * 6),
              jsonb_build_object('label', 'ONNX weighted score', 'value', sensitivity_weighted_score, 'points', sensitivity_weighted_score),
              jsonb_build_object('label', 'Security-sensitive files', 'value', security_sensitive_files, 'points', security_sensitive_files * 22),
              jsonb_build_object('label', 'Attack-surface files', 'value', attack_surface_files, 'points', attack_surface_files * 16),
              jsonb_build_object('label', 'Dependency files', 'value', dependency_files, 'points', dependency_files * 12),
              jsonb_build_object('label', 'Workflow/CI files', 'value', workflow_files, 'points', workflow_files * 12)
            )
          ),
          jsonb_build_object(
            'bucket', 'Reviewer survival',
            'points', reviewer_score,
            'items', jsonb_build_array(
              jsonb_build_object('label', 'Current approval survival rows', 'value', approval_survival_approvals, 'points', case when approval_survival_approvals > 0 then round((1 - approval_line_survival_rate) * 90) else 0 end),
              jsonb_build_object('label', 'Current approval avg survival', 'value', round(approval_line_survival_rate * 100, 1), 'unit', '%'),
              jsonb_build_object('label', 'Current approval overwritten lines', 'value', approval_cross_author_overwritten_lines, 'points', least(30, approval_cross_author_overwritten_lines * 3)),
              jsonb_build_object('label', 'Reviewer history rows', 'value', reviewer_history_count, 'points', case when approval_survival_approvals = 0 and reviewer_history_count > 0 then round((1 - reviewer_avg_line_survival_rate) * 80) else 0 end),
              jsonb_build_object('label', 'Reviewer history avg survival', 'value', round(reviewer_avg_line_survival_rate * 100, 1), 'unit', '%')
            ),
            'approval_survival_reviewers', approval_survival_reviewers,
            'reviewer_history', reviewer_history
          ),
          jsonb_build_object(
            'bucket', 'Friction',
            'points', friction_score,
            'items', jsonb_build_array(
              jsonb_build_object('label', 'Unresolved comments', 'value', unresolved_comments, 'points', unresolved_comments * 12),
              jsonb_build_object('label', 'Negative votes', 'value', negative_votes, 'points', negative_votes * 18),
              jsonb_build_object('label', 'Contradicted votes', 'value', least(positive_votes, negative_votes), 'points', least(positive_votes, negative_votes) * 28),
              jsonb_build_object('label', 'Comment volume', 'value', total_comments, 'points', round(sqrt(greatest(total_comments, 0)::numeric) * 7))
            )
          ),
          jsonb_build_object(
            'bucket', 'Rework',
            'points', rework_score,
            'items', jsonb_build_array(
              jsonb_build_object('label', 'Patch sets', 'value', patch_sets, 'points', patch_sets * 5),
              jsonb_build_object('label', 'Touched files', 'value', touched_files, 'points', touched_files * 3),
              jsonb_build_object('label', 'Changed lines', 'value', insertions + deletions, 'points', round(sqrt(greatest(insertions + deletions, 0)::numeric) * 4)),
              jsonb_build_object('label', 'Human reviewers', 'value', human_reviewers, 'points', human_reviewers * 6)
            )
          ),
          jsonb_build_object(
            'bucket', 'Stale',
            'points', stale_score,
            'items', jsonb_build_array(
              jsonb_build_object('label', 'Age days', 'value', age_days, 'points', stale_score)
            )
          )
        ) as score_contributors
      from scored
    )
    select jsonb_build_object(
      'generated_at', now(),
      'filters', jsonb_build_object(
        'repository_id', ${sqlLiteral(options.repositoryId || "")},
        'project', ${sqlLiteral(options.project || "")},
        'status', ${sqlLiteral(normalizedStatus)},
        'month', ${sqlLiteral(options.month || "")},
        'since', ${sqlLiteral(since || "")},
        'until', ${sqlLiteral(until || "")},
        'date_field', ${sqlLiteral(dateField)},
        'limit', ${limit},
        'keyword_repository_id', ${sqlLiteral(keywordRepositoryId)}
      ),
      'keyword_config', ${sqlLiteral(JSON.stringify(keywordConfig))}::jsonb,
      'review_risk_weights', jsonb_build_array(
        jsonb_build_object('bucket', 'Security', 'field', 'configured_keyword_weight_sum_capped_at_120', 'weight', 'per keyword config'),
        jsonb_build_object('bucket', 'Security', 'field', 'distinct_rule_keyword_kinds', 'weight', 6),
        jsonb_build_object('bucket', 'Security', 'field', 'onnx_40_to_54', 'weight', 6),
        jsonb_build_object('bucket', 'Security', 'field', 'onnx_55_to_69', 'weight', 14),
        jsonb_build_object('bucket', 'Security', 'field', 'onnx_70_plus', 'weight', 30),
        jsonb_build_object('bucket', 'Security', 'field', 'security_sensitive_files', 'weight', 22),
        jsonb_build_object('bucket', 'Security', 'field', 'attack_surface_files', 'weight', 16),
        jsonb_build_object('bucket', 'Security', 'field', 'dependency_files', 'weight', 12),
        jsonb_build_object('bucket', 'Security', 'field', 'workflow_files', 'weight', 12),
        jsonb_build_object('bucket', 'Reviewer survival', 'field', 'current_approval_avg_survival_gap', 'weight', 'up to 90'),
        jsonb_build_object('bucket', 'Reviewer survival', 'field', 'current_approval_overwritten_lines', 'weight', '3 each, cap 30'),
        jsonb_build_object('bucket', 'Reviewer survival', 'field', 'reviewer_history_avg_survival_gap', 'weight', 'up to 80'),
        jsonb_build_object('bucket', 'Friction', 'field', 'unresolved_comments', 'weight', 12),
        jsonb_build_object('bucket', 'Friction', 'field', 'negative_votes', 'weight', 18),
        jsonb_build_object('bucket', 'Friction', 'field', 'contradicted_votes', 'weight', 28),
        jsonb_build_object('bucket', 'Rework', 'field', 'patch_sets', 'weight', 5),
        jsonb_build_object('bucket', 'Rework', 'field', 'touched_files', 'weight', 3),
        jsonb_build_object('bucket', 'Stale', 'field', 'days_open_after_30', 'weight', '1 per 14 days')
      ),
      'review_risk_summary', jsonb_build_object(
        'proposed_reviews', (select count(*)::bigint from final_rows),
        'critical_reviews', (select count(*)::bigint from final_rows where risk_level = 'critical'),
        'high_reviews', (select count(*)::bigint from final_rows where risk_level in ('critical', 'high')),
        'avg_risk_score', (select round(avg(risk_score), 1) from final_rows),
        'max_risk_score', (select max(risk_score) from final_rows)
      ),
      'proposed_review_risk', coalesce((
        select jsonb_agg(to_jsonb(rows) order by risk_score desc, security_score desc, friction_score desc)
        from (
          select
            change_number,
            repository_id,
            left(subject, 150) as subject,
            project,
            branch,
            status,
            owner,
            owner_account_id,
            age_days,
            created_at,
            updated_at,
            insertions,
            deletions,
            (insertions + deletions)::bigint as changed_lines,
            review_messages,
            human_messages,
            automated_messages,
            patch_sets,
            human_reviewers,
            reviewer_author_ids,
            reviewers,
            approval_survival_approvals,
            approval_line_survival_rate,
            min_approval_line_survival_rate,
            approval_insertions_tracked,
            approval_surviving_lines,
            approval_cross_author_overwritten_lines,
            approval_survival_reviewers,
            reviewer_history_count,
            reviewer_avg_line_survival_rate,
            reviewer_min_line_survival_rate,
            reviewer_history_changes,
            reviewer_history,
            vote_events,
            positive_votes,
            negative_votes,
            total_comments,
            unresolved_comments,
            security_signal_mentions,
            distinct_signal_kinds,
            keyword_weighted_score,
            keyword_hits,
            security_scenario_hits,
            max_sensitivity_score,
            avg_sensitivity_score,
            sensitivity_ge40_messages,
            sensitivity_ge55_messages,
            sensitivity_ge70_messages,
            sensitivity_weighted_score,
            touched_files,
            security_sensitive_files,
            attack_surface_files,
            dependency_files,
            workflow_files,
            security_score,
            friction_score,
            rework_score,
            stale_score,
            reviewer_score,
            risk_score,
            risk_level,
            score_contributors,
            to_jsonb(risk_reasons) as risk_reasons,
            review_url
          from final_rows
          order by risk_score desc, security_score desc, friction_score desc
          limit ${limit}
        ) rows
      ), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

function emptyReviewRiskStats() {
  return {
    review_messages: 0,
    human_messages: 0,
    automated_messages: 0,
    patch_sets: 0,
    security_signal_mentions: 0,
    keyword_weighted_score: 0,
    keywordKindIds: new Set(),
    keyword_hits: [],
    vote_events: 0,
    positive_votes: 0,
    negative_votes: 0,
    security_scenario_hits: 0,
    sensitivityScores: [],
    sensitivity_ge40_messages: 0,
    sensitivity_ge55_messages: 0,
    sensitivity_ge70_messages: 0,
    sensitivity_weighted_score: 0,
    touchedFiles: new Set(),
    securitySensitiveFiles: new Set(),
    attackSurfaceFiles: new Set(),
    dependencyFiles: new Set(),
    workflowFiles: new Set(),
    approval_survival_approvals: 0,
    approval_line_survival_rate_sum: 0,
    min_approval_line_survival_rate: null,
    approval_insertions_tracked: 0,
    approval_surviving_lines: 0,
    approval_cross_author_overwritten_lines: 0,
    approval_survival_reviewers: [],
    approval_survival_keys: new Set(),
    implementation_concern_density_per_touched_file: 0,
    implementation_concern_messages: 0,
    implementation_repeated_concern_file_count: 0,
    implementation_author_response_ratio: 0,
    implementation_reviewer_spread_after_first_concern: 0,
    implementation_patch_sets_after_first_concern: 0,
    implementation_distinct_concern_patch_sets: 0,
    implementation_last_concern_patch_set: 0,
    implementation_concern_span_patch_sets: 0,
    implementation_concerns_after_positive_vote: 0,
    implementation_security_sensitive_repeated_concern_file_count: 0,
    implementation_small_change_high_friction: false,
    implementation_signal_score: 0,
    implementation_strong_concern_score: 0,
    implementation_strong_concern_messages: 0,
    implementation_low_concern_score: 0,
    implementation_file_specific_strong_concern_messages: 0,
    implementation_strong_concern_kinds: new Set(),
    implementation_human_message_count: 0,
  };
}

function applyReviewRiskMetadata(rowStats, metadata, context = {}) {
  const namespace = String(metadata.namespace || "");
  const key = String(metadata.key || "");
  const value = metadata.value;
  if (namespace === "review.approval" && key === "vote") {
    if (String(value?.action || "") !== "vote") return;
    const voteValue = numberValue(value?.value);
    rowStats.vote_events += 1;
    if (voteValue > 0) rowStats.positive_votes += 1;
    if (voteValue < 0) rowStats.negative_votes += 1;
    return;
  }
  if (namespace === "security.scenario") {
    rowStats.security_scenario_hits += 1;
    return;
  }
  if (namespace === "security.signal") {
    const category = String(value?.category || key || "security_signal");
    const term = String(value?.term || key || category);
    const weight = metadataSecuritySignalWeight(category, key);
    rowStats.security_signal_mentions += 1;
    rowStats.keyword_weighted_score += weight;
    rowStats.keywordKindIds.add(`metadata:${key || category}`);
    rowStats.keyword_hits.push({
      id: `metadata:${key || category}`,
      label: `Metadata: ${category}`,
      color: "#245da8",
      weight,
      order: 100,
      term,
    });
    return;
  }
  if (namespace === "security.sensitivity" && key === "score") {
    const score = numberValue(value?.score);
    rowStats.sensitivityScores.push(score);
    if (score >= 70) {
      rowStats.sensitivity_ge70_messages += 1;
      rowStats.sensitivity_weighted_score += 40;
    } else if (score >= 55) {
      rowStats.sensitivity_ge55_messages += 1;
      rowStats.sensitivity_weighted_score += 18;
    } else if (score >= 40) {
      rowStats.sensitivity_ge40_messages += 1;
      rowStats.sensitivity_weighted_score += 8;
    }
    return;
  }
  if (namespace === "review.concern" && key === "signal") {
    applyReviewConcernMetadata(rowStats, value, context);
    return;
  }
  if (namespace === "review.implementation_risk") {
    applyImplementationRiskMetadata(rowStats, key, value);
    return;
  }
  if (namespace === "code.file" && key === "path") {
    const path = stringValue(value);
    if (path && !path.includes("PATCHSET_LEVEL")) {
      rowStats.touchedFiles.add(path);
      if (isDependencyPath(path)) rowStats.dependencyFiles.add(path);
      if (isWorkflowPath(path)) rowStats.workflowFiles.add(path);
    }
    return;
  }
  if (namespace === "code.file_role" && value && typeof value === "object") {
    const role = String(value.role || "");
    const path = String(value.path || "");
    if (!path) return;
    if (role === "security_sensitive") rowStats.securitySensitiveFiles.add(path);
    if (role === "attack_surface") rowStats.attackSurfaceFiles.add(path);
    if (role === "dependency_manifest") rowStats.dependencyFiles.add(path);
    if (role === "cicd_workflow") rowStats.workflowFiles.add(path);
  }
}

function reviewConcernTerms(value) {
  return Array.isArray(value?.concern_terms) ? value.concern_terms : [];
}

function reviewConcernTermWeight(term) {
  return numberValue(term?.weight ?? term?.score);
}

function reviewConcernTermKind(term) {
  return String(term?.type || term?.kind || term?.category || "").trim().toLowerCase();
}

function isStrongReviewConcernTerm(term) {
  const kind = reviewConcernTermKind(term);
  const weight = reviewConcernTermWeight(term);
  return weight >= 7 || ["correctness", "security_access", "privacy_secrets", "surprise_smell"].includes(kind);
}

function isRealReviewFilePath(path) {
  const text = String(path || "").trim();
  return text && text !== "PATCHSET_LEVEL" && !text.includes("PATCHSET_LEVEL");
}

function applyReviewConcernMetadata(rowStats, value, context = {}) {
  if (!value || typeof value !== "object" || value.is_concern !== true) return;
  if (value.automated === true || String(value.automated) === "true") return;
  const authorId = String(value.author_id || "");
  const ownerAuthorId = String(context.ownerAuthorId || "");
  if (ownerAuthorId && authorId === ownerAuthorId) return;
  const terms = reviewConcernTerms(value);
  const strongTerms = terms.filter(isStrongReviewConcernTerm);
  const strongScore = strongTerms.reduce((sum, term) => sum + reviewConcernTermWeight(term), 0);
  const concernScore = numberValue(value.concern_score);
  const lowScore = Math.max(0, concernScore - strongScore);

  if (strongScore > 0) {
    rowStats.implementation_strong_concern_messages += 1;
    rowStats.implementation_strong_concern_score += strongScore;
    if (isRealReviewFilePath(value.file_path)) {
      rowStats.implementation_file_specific_strong_concern_messages += 1;
    }
    for (const term of strongTerms) {
      const kind = reviewConcernTermKind(term);
      if (kind) rowStats.implementation_strong_concern_kinds.add(kind);
    }
  }

  rowStats.implementation_low_concern_score += lowScore;
}

function applyImplementationRiskMetadata(rowStats, key, value) {
  const payload = key === "signals" && value && typeof value === "object" ? value : { [key]: value };
  if (payload.concern_density_per_touched_file !== undefined) {
    rowStats.implementation_concern_density_per_touched_file = numberValue(payload.concern_density_per_touched_file);
  }
  if (payload.concern_message_count !== undefined) {
    rowStats.implementation_concern_messages = numberValue(payload.concern_message_count);
  }
  if (payload.repeated_concern_file_count !== undefined) {
    rowStats.implementation_repeated_concern_file_count = numberValue(payload.repeated_concern_file_count);
  }
  if (payload.author_response_ratio !== undefined) {
    rowStats.implementation_author_response_ratio = numberValue(payload.author_response_ratio);
  }
  if (payload.reviewer_spread_after_first_concern !== undefined) {
    rowStats.implementation_reviewer_spread_after_first_concern = numberValue(payload.reviewer_spread_after_first_concern);
  }
  if (payload.patch_sets_after_first_concern !== undefined) {
    rowStats.implementation_patch_sets_after_first_concern = numberValue(payload.patch_sets_after_first_concern);
  }
  if (payload.distinct_concern_patch_sets !== undefined) {
    rowStats.implementation_distinct_concern_patch_sets = numberValue(payload.distinct_concern_patch_sets);
  }
  if (payload.last_concern_patch_set !== undefined) {
    rowStats.implementation_last_concern_patch_set = numberValue(payload.last_concern_patch_set);
  }
  if (payload.concern_span_patch_sets !== undefined) {
    rowStats.implementation_concern_span_patch_sets = numberValue(payload.concern_span_patch_sets);
  }
  if (payload.concerns_after_positive_vote !== undefined) {
    rowStats.implementation_concerns_after_positive_vote = numberValue(payload.concerns_after_positive_vote);
  }
  if (payload.security_sensitive_repeated_concern_file_count !== undefined) {
    rowStats.implementation_security_sensitive_repeated_concern_file_count = numberValue(payload.security_sensitive_repeated_concern_file_count);
  }
  if (payload.small_change_high_friction !== undefined) {
    rowStats.implementation_small_change_high_friction = payload.small_change_high_friction === true || String(payload.small_change_high_friction) === "true";
  }
  if (payload.implementation_signal_score !== undefined) {
    rowStats.implementation_signal_score = numberValue(payload.implementation_signal_score);
  }
  if (payload.human_message_count !== undefined) {
    rowStats.implementation_human_message_count = numberValue(payload.human_message_count);
  }
}

function implementationRiskBreakdown(rowStats) {
  const strongConcernPoints = Math.min(72, rowStats.implementation_strong_concern_score * 2);
  const fileSpecificStrongPoints = Math.min(34, rowStats.implementation_file_specific_strong_concern_messages * 10);
  const repeatedFilePoints = Math.min(36, rowStats.implementation_repeated_concern_file_count * 12);
  const sensitiveRepeatedPoints = Math.min(48, rowStats.implementation_security_sensitive_repeated_concern_file_count * 24);
  const afterApprovalPoints = Math.min(28, rowStats.implementation_concerns_after_positive_vote * 8);
  const densityPoints = Math.min(24, Math.round(rowStats.implementation_concern_density_per_touched_file * 8));
  const strongKindPoints = Math.min(18, rowStats.implementation_strong_concern_kinds.size * 6);
  const authorResponsePoints = rowStats.implementation_author_response_ratio >= 0.4
    && rowStats.implementation_strong_concern_messages >= 2
    ? 10
    : 0;
  const aggregateFallbackPoints = rowStats.implementation_strong_concern_score === 0
    ? Math.min(30, Math.round(rowStats.implementation_signal_score * 0.35))
    : 0;
  const items = [
    { label: "Strong concern score", value: rowStats.implementation_strong_concern_score, points: strongConcernPoints },
    { label: "File-specific strong concerns", value: rowStats.implementation_file_specific_strong_concern_messages, points: fileSpecificStrongPoints },
    { label: "Repeated-concern files", value: rowStats.implementation_repeated_concern_file_count, points: repeatedFilePoints },
    { label: "Repeated concerns on security-sensitive files", value: rowStats.implementation_security_sensitive_repeated_concern_file_count, points: sensitiveRepeatedPoints },
    { label: "Concerns at/after first approval", value: rowStats.implementation_concerns_after_positive_vote, points: afterApprovalPoints },
    { label: "Concern density per touched file", value: rowStats.implementation_concern_density_per_touched_file, points: densityPoints },
    { label: "Strong concern categories", value: rowStats.implementation_strong_concern_kinds.size, points: strongKindPoints },
    { label: "Author response ratio", value: roundNumber(rowStats.implementation_author_response_ratio * 100, 1), unit: "%", points: authorResponsePoints },
    { label: "Aggregate fallback score", value: rowStats.implementation_signal_score, points: aggregateFallbackPoints },
  ];
  const points = Math.min(reviewRiskCaps.implementation, items.reduce((sum, item) => sum + numberValue(item.points), 0));
  return { points, items };
}

function metadataSecuritySignalWeight(category, key = "") {
  const text = `${category} ${key}`.toLowerCase();
  if (/(vulnerability|explicit_security|security_keyword|identifier|cve|ghsa)/.test(text)) return 15;
  if (/(authorization|credential|crypto|signature|secret|token|permission)/.test(text)) return 12;
  if (/(data_integrity|checksum|etag|hash|corrupt|quarantine)/.test(text)) return 10;
  if (/(input_validation|parser|request_body|unsafe_deserialization|pickle|xml|chunked|oversized|truncated)/.test(text)) return 10;
  if (/(runtime_dependency|workflow|cicd|dependency)/.test(text)) return 8;
  return 6;
}

function applyApprovalSurvival(rowStats, value) {
  const dedupeKey = [
    value.reviewer_key || value.gerrit_account_id || value.reviewer_author_id || "",
    value.commit_sha || "",
    value.approval_message_id || value.approval_patch_set || value.raw || value.label || "",
  ].join("|");
  if (rowStats.approval_survival_keys.has(dedupeKey)) return;
  rowStats.approval_survival_keys.add(dedupeKey);
  const rate = numberValue(value.line_survival_rate);
  const insertions = numberValue(value.commit_insertions_tracked);
  const surviving = numberValue(value.surviving_lines);
  const overwritten = numberValue(value.cross_author_overwritten_lines);
  rowStats.approval_survival_approvals += 1;
  rowStats.approval_line_survival_rate_sum += rate;
  rowStats.min_approval_line_survival_rate = rowStats.min_approval_line_survival_rate === null
    ? rate
    : Math.min(rowStats.min_approval_line_survival_rate, rate);
  rowStats.approval_insertions_tracked += insertions;
  rowStats.approval_surviving_lines += surviving;
  rowStats.approval_cross_author_overwritten_lines += overwritten;
  rowStats.approval_survival_reviewers.push({
    reviewer: String(value.reviewer_key || ""),
    reviewer_name: String(value.reviewer_name || ""),
    reviewer_email: String(value.reviewer_email || ""),
    gerrit_account_id: String(value.gerrit_account_id || ""),
    reviewer_author_id: String(value.reviewer_author_id || ""),
    approval_patch_set: numberValue(value.approval_patch_set),
    approval_label: String(value.label || ""),
    approval_value: numberValue(value.value),
    line_survival_rate: rate,
    insertions_tracked: insertions,
    surviving_lines: surviving,
    cross_author_overwritten_lines: overwritten,
    labels: Array.isArray(value.labels) ? value.labels : [],
  });
  rowStats.approval_survival_reviewers.sort((left, right) =>
    left.line_survival_rate - right.line_survival_rate || left.reviewer.localeCompare(right.reviewer)
  );
}

function scoreReviewRiskRow(change, rowStats, participantIds, reviewerNames, reviewerHistory, owner, authorCompetenceInput = {}) {
  const distinctSignalKinds = rowStats.keywordKindIds.size;
  const maxSensitivity = rowStats.sensitivityScores.length ? Math.max(...rowStats.sensitivityScores) : 0;
  const avgSensitivity = rowStats.sensitivityScores.length ? average(rowStats.sensitivityScores) : 0;
  const authorCompetence = computeAuthorCompetence(authorCompetenceInput);
  const approvalAvg = rowStats.approval_survival_approvals
    ? rowStats.approval_line_survival_rate_sum / rowStats.approval_survival_approvals
    : 0;
  const reviewerAvg = reviewerHistory.length ? average(reviewerHistory.map((row) => row.line_survival_rate)) : 0;
  const reviewerMin = reviewerHistory.length ? Math.min(...reviewerHistory.map((row) => row.line_survival_rate)) : 0;
  const reviewerHistoryChanges = reviewerHistory.reduce((sum, row) => sum + numberValue(row.reviewed_changes_count), 0);
  const changedLines = numberValue(change.insertions) + numberValue(change.deletions);
  const changedLinesScore = changedLinesRiskScore(changedLines);
  const securityScore = Math.min(
    reviewRiskCaps.security,
    Math.min(rowStats.keyword_weighted_score, keywordScoreCap)
      + distinctSignalKinds * 8
      + rowStats.security_scenario_hits * 3
      + rowStats.sensitivity_weighted_score
      + rowStats.securitySensitiveFiles.size * 28
      + rowStats.attackSurfaceFiles.size * 22
      + rowStats.dependencyFiles.size * 16
      + rowStats.workflowFiles.size * 16,
  );
  const frictionScore = Math.min(
    reviewRiskCaps.friction,
    numberValue(change.unresolved_comments) * 10
      + rowStats.negative_votes * 16
      + Math.min(rowStats.positive_votes, rowStats.negative_votes) * 24
      + Math.round(Math.sqrt(Math.max(numberValue(change.total_comments), 0)) * 5)
      + Math.min(14, rowStats.implementation_reviewer_spread_after_first_concern * 3)
      + Math.min(10, rowStats.implementation_distinct_concern_patch_sets * 2)
      + (rowStats.implementation_small_change_high_friction ? 10 : 0),
  );
  const reworkScore = Math.min(
    reviewRiskCaps.rework,
    Math.round(rowStats.patch_sets * 1.5)
      + Math.round(rowStats.touchedFiles.size * 1.25)
      + participantIds.length * 2
      + Math.min(12, rowStats.implementation_patch_sets_after_first_concern * 2)
      + Math.min(8, rowStats.implementation_concern_span_patch_sets * 2),
  );
  const ageDays = ageDaysFromTimestamp(change.created_at);
  const staleScore = String(change.status || "").toUpperCase() === "NEW"
    ? Math.min(reviewRiskCaps.stale, Math.floor(Math.max(ageDays - 30, 0) / 14))
    : 0;
  const reviewerScore = Math.min(
    reviewRiskCaps.reviewer,
    rowStats.approval_survival_approvals > 0
      ? Math.round((1 - approvalAvg) * 90) + Math.min(30, rowStats.approval_cross_author_overwritten_lines * 3)
      : reviewerHistory.length > 0
        ? Math.round((1 - reviewerAvg) * 80) + Math.min(30, Math.max(0, 3 - reviewerHistory.length) * 8)
        : 0,
  );
  const implementationBreakdown = implementationRiskBreakdown(rowStats);
  const implementationScore = implementationBreakdown.points;
  const authorScore = authorCompetence.risk_score;
  const flatRiskScore = securityScore + authorScore + implementationScore + frictionScore + reworkScore + changedLinesScore + staleScore + reviewerScore;
  const missionPriority = computeMissionReviewPriority({
    change,
    rowStats,
    authorCompetence,
    reviewerHistory,
    participantCount: participantIds.length,
    securityScore,
    implementationScore,
    frictionScore,
    reworkScore,
    changedLinesScore,
    staleScore,
    reviewerScore,
  });
  const riskScore = missionPriority.score;
  const riskLevel = missionPriority.risk_level;
  const scoreItems = reviewRiskScoreItems({
    rowStats,
    authorCompetence,
    authorScore,
    reviewerScore,
    implementationScore,
    frictionScore,
    reworkScore,
    changedLinesScore,
    staleScore,
    distinctSignalKinds,
  });
  const bucketScore = reviewRiskWeightedBucketScore(scoreItems);
  const riskReasons = [
    missionPriority.priority_lane ? `lane ${missionPriority.priority_lane}` : null,
    missionPriority.security_locus ? `locus ${missionPriority.security_locus}` : null,
    missionPriority.change_shape ? `shape ${missionPriority.change_shape}` : null,
    authorCompetence.has_data
      ? `author competence ${authorCompetence.competence_score}/100, confidence ${roundNumber(authorCompetence.confidence * 100, 1)}%, ${authorCompetence.authored_git_commits} git commits, ${authorCompetence.authored_reviews_count} authored reviews`
      : "author competence unknown",
    rowStats.sensitivity_ge40_messages > 0 ? `${rowStats.sensitivity_ge40_messages} ONNX >=40` : null,
    rowStats.sensitivity_ge55_messages > 0 ? `${rowStats.sensitivity_ge55_messages} ONNX >=55` : null,
    rowStats.sensitivity_ge70_messages > 0 ? `${rowStats.sensitivity_ge70_messages} ONNX >=70` : null,
    rowStats.security_signal_mentions > 0 ? `${rowStats.security_signal_mentions} rule keyword hits` : null,
    rowStats.securitySensitiveFiles.size > 0 ? `${rowStats.securitySensitiveFiles.size} security-sensitive files` : null,
    rowStats.attackSurfaceFiles.size > 0 ? `${rowStats.attackSurfaceFiles.size} attack-surface files` : null,
    rowStats.dependencyFiles.size > 0 ? `${rowStats.dependencyFiles.size} dependency files` : null,
    rowStats.workflowFiles.size > 0 ? `${rowStats.workflowFiles.size} workflow/CI files` : null,
    implementationScore > 0 ? `implementation risk ${implementationScore}` : null,
    rowStats.implementation_concern_messages > 0 ? `${rowStats.implementation_concern_messages} concern messages` : null,
    rowStats.implementation_repeated_concern_file_count > 0 ? `${rowStats.implementation_repeated_concern_file_count} repeated-concern files` : null,
    rowStats.implementation_security_sensitive_repeated_concern_file_count > 0 ? `${rowStats.implementation_security_sensitive_repeated_concern_file_count} repeated concerns on security-sensitive files` : null,
    rowStats.implementation_reviewer_spread_after_first_concern > 0 ? `${rowStats.implementation_reviewer_spread_after_first_concern} reviewers after first concern` : null,
    rowStats.implementation_patch_sets_after_first_concern > 0 ? `${rowStats.implementation_patch_sets_after_first_concern} patch sets after first concern` : null,
    rowStats.implementation_distinct_concern_patch_sets > 0 ? `${rowStats.implementation_distinct_concern_patch_sets} patch sets with concerns` : null,
    rowStats.implementation_concerns_after_positive_vote > 0 ? `${rowStats.implementation_concerns_after_positive_vote} concerns at/after first approval` : null,
    rowStats.implementation_small_change_high_friction ? "small change with high review friction" : null,
    rowStats.implementation_strong_concern_messages > 0 ? `${rowStats.implementation_strong_concern_messages} strong concern messages` : null,
    rowStats.implementation_file_specific_strong_concern_messages > 0 ? `${rowStats.implementation_file_specific_strong_concern_messages} file-specific strong concerns` : null,
    numberValue(change.unresolved_comments) > 0 ? `${change.unresolved_comments} unresolved comments` : null,
    rowStats.negative_votes > 0 ? `${rowStats.negative_votes} negative votes` : null,
    changedLinesScore > 0 ? `changed lines score ${changedLinesScore} from ${changedLines} changed lines` : null,
    rowStats.patch_sets > 8 ? `${rowStats.patch_sets} patch sets` : null,
    rowStats.approval_survival_approvals > 0 ? `${rowStats.approval_survival_approvals} approval survival rows, avg ${roundNumber(approvalAvg * 100, 1)}%` : null,
    rowStats.approval_survival_approvals === 0 && reviewerHistory.length > 0 ? `${reviewerHistory.length} reviewer history rows, avg ${roundNumber(reviewerAvg * 100, 1)}%` : null,
    ageDays > 120 ? `${ageDays} days open` : null,
  ].filter(Boolean);
  return {
    change_number: String(change.change_number || ""),
    repository_id: String(change.repository_id || ""),
    subject: String(change.subject || "").slice(0, 150),
    project: String(change.project || ""),
    branch: String(change.branch || ""),
    status: String(change.status || ""),
    owner,
    owner_account_id: String(change.owner_account_id || ""),
    age_days: ageDays,
    created_at: String(change.created_at || ""),
    updated_at: String(change.updated_at || ""),
    insertions: numberValue(change.insertions),
    deletions: numberValue(change.deletions),
    changed_lines: changedLines,
    changed_files: Array.isArray(change.changed_files) ? change.changed_files : [],
    review_messages: rowStats.review_messages,
    human_messages: rowStats.human_messages,
    automated_messages: rowStats.automated_messages,
    patch_sets: rowStats.patch_sets,
    human_reviewers: participantIds.length,
    reviewer_author_ids: participantIds,
    reviewers: reviewerNames.sort().join(", ").slice(0, 180),
    approval_survival_approvals: rowStats.approval_survival_approvals,
    approval_line_survival_rate: roundNumber(approvalAvg, 4),
    min_approval_line_survival_rate: roundNumber(rowStats.min_approval_line_survival_rate || 0, 4),
    approval_insertions_tracked: rowStats.approval_insertions_tracked,
    approval_surviving_lines: rowStats.approval_surviving_lines,
    approval_cross_author_overwritten_lines: rowStats.approval_cross_author_overwritten_lines,
    approval_survival_reviewers: rowStats.approval_survival_reviewers,
    reviewer_history_count: reviewerHistory.length,
    reviewer_avg_line_survival_rate: roundNumber(reviewerAvg, 4),
    reviewer_min_line_survival_rate: roundNumber(reviewerMin, 4),
    reviewer_history_changes: reviewerHistoryChanges,
    reviewer_history: reviewerHistory,
    vote_events: rowStats.vote_events,
    positive_votes: rowStats.positive_votes,
    negative_votes: rowStats.negative_votes,
    total_comments: numberValue(change.total_comments),
    unresolved_comments: numberValue(change.unresolved_comments),
    security_signal_mentions: rowStats.security_signal_mentions,
    distinct_signal_kinds: distinctSignalKinds,
    keyword_weighted_score: rowStats.keyword_weighted_score,
    keyword_hits: distinctKeywordHits(rowStats.keyword_hits),
    security_scenario_hits: rowStats.security_scenario_hits,
    max_sensitivity_score: roundNumber(maxSensitivity, 2),
    avg_sensitivity_score: roundNumber(avgSensitivity, 2),
    sensitivity_ge40_messages: rowStats.sensitivity_ge40_messages,
    sensitivity_ge55_messages: rowStats.sensitivity_ge55_messages,
    sensitivity_ge70_messages: rowStats.sensitivity_ge70_messages,
    sensitivity_weighted_score: rowStats.sensitivity_weighted_score,
    touched_files: rowStats.touchedFiles.size,
    security_sensitive_files: rowStats.securitySensitiveFiles.size,
    attack_surface_files: rowStats.attackSurfaceFiles.size,
    dependency_files: rowStats.dependencyFiles.size,
    workflow_files: rowStats.workflowFiles.size,
    author_competence_score: authorCompetence.competence_score,
    author_score: authorScore,
    author_competence_known: authorCompetence.has_data,
    author_competence_confidence: authorCompetence.confidence,
    author_code_confidence: authorCompetence.code_confidence,
    author_review_confidence: authorCompetence.review_confidence,
    author_experience_confidence: authorCompetence.experience_confidence,
    author_experience_score: authorCompetence.experience_score,
    author_low_analysis_factor: authorCompetence.low_analysis_factor,
    author_line_survival_rate: roundNumber(authorCompetence.line_survival_rate, 4),
    author_commits_analyzed: authorCompetence.commits_analyzed,
    author_commits_seen: authorCompetence.commits_seen,
    author_authored_git_commits: authorCompetence.authored_git_commits,
    author_authored_git_changed_lines: authorCompetence.authored_git_changed_lines,
    author_insertions_tracked: authorCompetence.insertions_tracked,
    author_surviving_lines: authorCompetence.surviving_lines,
    author_cross_author_overwrite_rate: roundNumber(authorCompetence.cross_author_overwrite_rate, 4),
    author_self_rework_rate: roundNumber(authorCompetence.self_rework_rate, 4),
    author_cross_author_overwritten_lines: authorCompetence.cross_author_overwritten_lines,
    author_self_reworked_lines: authorCompetence.self_reworked_lines,
    author_git_author_id: authorCompetence.owner_git_author_id,
    author_gerrit_author_id: authorCompetence.owner_author_id,
    author_email: authorCompetence.owner_email,
    author_matched_git_name: authorCompetence.matched_git_name,
    author_matched_git_email: authorCompetence.matched_git_email,
    author_match_method: authorCompetence.match_method,
    author_match_rank: authorCompetence.match_rank,
    author_authored_reviews_count: authorCompetence.authored_reviews_count,
    author_merged_reviews_count: authorCompetence.merged_reviews_count,
    author_abandoned_reviews_count: authorCompetence.abandoned_reviews_count,
    author_open_reviews_count: authorCompetence.open_reviews_count,
    author_merged_rate: roundNumber(authorCompetence.merged_rate, 4),
    author_abandoned_rate: roundNumber(authorCompetence.abandoned_rate, 4),
    author_avg_changed_lines: roundNumber(authorCompetence.avg_changed_lines, 1),
    author_avg_patch_sets: roundNumber(authorCompetence.avg_patch_sets, 2),
    author_avg_human_messages: roundNumber(authorCompetence.avg_human_messages, 2),
    author_avg_human_reviewers: roundNumber(authorCompetence.avg_human_reviewers, 2),
    author_avg_unresolved_comments: roundNumber(authorCompetence.avg_unresolved_comments, 2),
    author_avg_implementation_signal_score: roundNumber(authorCompetence.avg_implementation_signal_score, 2),
    author_avg_concern_messages: roundNumber(authorCompetence.avg_concern_messages, 2),
    author_high_implementation_reviews: authorCompetence.high_implementation_reviews,
    author_small_change_high_friction_reviews: authorCompetence.small_change_high_friction_reviews,
    author_security_experience_reviews: authorCompetence.security_experience_reviews,
    author_sensitive_file_reviews: authorCompetence.sensitive_file_reviews,
    security_score: securityScore,
    bucket_score: bucketScore.score,
    bucket_score_details: bucketScore,
    score_items: scoreItems,
    flat_risk_score: flatRiskScore,
    deep_review_priority_score: riskScore,
    priority_lane: missionPriority.priority_lane,
    priority_rank: missionPriority.priority_rank,
    security_locus: missionPriority.security_locus,
    security_locus_rank: missionPriority.security_locus_rank,
    change_shape: missionPriority.change_shape,
    author_competence_bucket: missionPriority.author_bucket,
    reviewer_competence_bucket: missionPriority.reviewer_bucket,
    process_smell_bucket: missionPriority.process_bucket,
    mission_priority_reasons: missionPriority.reasons,
    implementation_score: implementationScore,
    implementation_concern_density_per_touched_file: roundNumber(rowStats.implementation_concern_density_per_touched_file, 3),
    implementation_concern_messages: rowStats.implementation_concern_messages,
    implementation_repeated_concern_file_count: rowStats.implementation_repeated_concern_file_count,
    implementation_author_response_ratio: roundNumber(rowStats.implementation_author_response_ratio, 3),
    implementation_reviewer_spread_after_first_concern: rowStats.implementation_reviewer_spread_after_first_concern,
    implementation_patch_sets_after_first_concern: rowStats.implementation_patch_sets_after_first_concern,
    implementation_distinct_concern_patch_sets: rowStats.implementation_distinct_concern_patch_sets,
    implementation_last_concern_patch_set: rowStats.implementation_last_concern_patch_set,
    implementation_concern_span_patch_sets: rowStats.implementation_concern_span_patch_sets,
    implementation_concerns_after_positive_vote: rowStats.implementation_concerns_after_positive_vote,
    implementation_security_sensitive_repeated_concern_file_count: rowStats.implementation_security_sensitive_repeated_concern_file_count,
    implementation_small_change_high_friction: rowStats.implementation_small_change_high_friction,
    implementation_signal_score: rowStats.implementation_signal_score,
    implementation_strong_concern_score: rowStats.implementation_strong_concern_score,
    implementation_strong_concern_messages: rowStats.implementation_strong_concern_messages,
    implementation_low_concern_score: rowStats.implementation_low_concern_score,
    implementation_file_specific_strong_concern_messages: rowStats.implementation_file_specific_strong_concern_messages,
    implementation_strong_concern_kinds: Array.from(rowStats.implementation_strong_concern_kinds).sort(),
    implementation_human_message_count: rowStats.implementation_human_message_count,
    friction_score: frictionScore,
    rework_score: reworkScore,
    changed_lines_score: changedLinesScore,
    stale_score: staleScore,
    reviewer_score: reviewerScore,
    risk_score: riskScore,
    risk_level: riskLevel,
    score_contributors: scoreContributorBuckets(rowStats, {
      securityScore,
      authorScore,
      authorCompetence,
      frictionScore,
      reworkScore,
      changedLinesScore,
      staleScore,
      reviewerScore,
      implementationScore,
      implementationBreakdown,
      distinctSignalKinds,
      approvalAvg,
      reviewerAvg,
      reviewerHistory,
      missionPriority,
      flatRiskScore,
      participantCount: participantIds.length,
      change,
      ageDays,
    }),
    risk_reasons: riskReasons,
    review_url: String(change.review_url || ""),
  };
}

function computeMissionReviewPriority(context) {
  const {
    change,
    rowStats,
    authorCompetence,
    reviewerHistory,
    participantCount,
    securityScore,
    implementationScore,
    frictionScore,
    reworkScore,
    changedLinesScore,
    staleScore,
    reviewerScore,
  } = context;
  const shape = classifyReviewChangeShape(change, rowStats);
  const locus = classifyReviewSecurityLocus(change, rowStats, securityScore, shape);
  const author = classifyReviewAuthorCompetence(authorCompetence);
  const reviewer = classifyReviewReviewerCompetence(reviewerHistory, participantCount, rowStats, reviewerScore);
  const process = classifyReviewProcessSmell(rowStats, change, implementationScore, frictionScore, reworkScore);

  let lane = "watch";
  if (locus.name === "suppressed_mechanical") {
    lane = "suppressed_mechanical";
  } else if (locus.name === "process_only_locus") {
    lane = process.name === "highly_smelly" ? "process_smell_watch" : "process_only_locus";
  } else if (locus.name === "critical_locus") {
    if (
      process.name === "highly_smelly"
      || ((author.name === "weak_known" || author.name === "thin_unknown") && process.name !== "calm")
      || ((reviewer.name === "weak_or_missing_review" || reviewer.name === "weak_approval_survival") && process.name === "smelly")
    ) {
      lane = "urgent_compute";
    } else if (
      process.name === "smelly"
      || author.name === "weak_known"
      || author.name === "thin_unknown"
      || reviewer.name === "weak_or_missing_review"
      || reviewer.name === "weak_approval_survival"
      || reviewer.name === "strong_but_struggled"
    ) {
      lane = "high_compute";
    } else if (author.name === "strong_known" && reviewer.name === "strong_clean_review" && process.name === "calm") {
      lane = "security_relevant_routine";
    } else {
      lane = "medium_high_compute";
    }
  } else if (locus.name === "important_locus") {
    if (process.name === "highly_smelly" && (author.risk >= 45 || reviewer.risk >= 35)) {
      lane = "high_compute";
    } else if (process.name !== "calm" || author.risk >= 55 || reviewer.risk >= 45) {
      lane = "medium_high_compute";
    } else {
      lane = "watch";
    }
  } else if (process.name === "highly_smelly" && (author.risk >= 55 || reviewer.risk >= 45)) {
    lane = "process_smell_watch";
  }

  const laneBase = {
    urgent_compute: 420,
    high_compute: 330,
    medium_high_compute: 250,
    security_relevant_routine: 180,
    process_smell_watch: 170,
    process_only_locus: 110,
    watch: 90,
    suppressed_mechanical: 20,
  }[lane] ?? 90;
  const humanProcessScore = Math.round(
    author.risk * 0.95
      + reviewer.risk * 0.75
      + process.risk * 0.9
      + Math.min(45, Math.round(reworkScore * 0.45))
      + Math.min(35, Math.round((changedLinesScore || 0) * 0.35))
      + Math.min(18, Math.round(staleScore * 0.4)),
  );
  const securityContribution = lane === "suppressed_mechanical"
    ? 0
    : lane === "process_only_locus" || lane === "process_smell_watch"
      ? Math.min(45, Math.round(securityScore * 0.12))
      : Math.min(90, Math.round(locus.rank * 14 + securityScore * 0.08));
  const score = Math.max(0, Math.min(999, laneBase + securityContribution + humanProcessScore));
  const priorityRank = {
    urgent_compute: 70,
    high_compute: 60,
    medium_high_compute: 50,
    security_relevant_routine: 40,
    process_smell_watch: 35,
    process_only_locus: 25,
    watch: 20,
    suppressed_mechanical: 5,
  }[lane] ?? 20;
  return {
    score,
    risk_level: score >= 620 ? "critical" : score >= 480 ? "high" : score >= 300 ? "elevated" : "watch",
    priority_lane: lane,
    priority_rank: priorityRank,
    security_locus: locus.name,
    security_locus_rank: locus.rank,
    change_shape: shape.name,
    author_bucket: author.name,
    reviewer_bucket: reviewer.name,
    process_bucket: process.name,
    reasons: [
      `${locus.name} from ${locus.reasons.join(", ") || "generic evidence"}`,
      `${author.name}: ${author.reason}`,
      `${reviewer.name}: ${reviewer.reason}`,
      `${process.name}: ${process.reason}`,
      `${shape.name}: ${shape.reason}`,
    ],
  };
}

function classifyReviewChangeShape(change, rowStats) {
  const subject = String(change.subject || "").toLowerCase();
  const changedLines = numberValue(change.insertions) + numberValue(change.deletions);
  const rawChangedFiles = Array.isArray(change.changed_files) ? change.changed_files : [];
  const paths = (rawChangedFiles.length ? rawChangedFiles : Array.from(rowStats.touchedFiles || []))
    .map((path) => String(path || ""))
    .filter(Boolean);
  const runtimePaths = paths.filter((path) => !isTestPath(path) && !isDocPath(path) && !isCiPath(path));
  if (changedLines === 0 || /^merge remote-tracking|^merge .*master|merge branch/.test(subject)) {
    return { name: "merge_only", reason: "merge or zero changed lines" };
  }
  if (paths.length && runtimePaths.length === 0 && paths.some(isTestPath)) {
    return { name: "test_only", reason: "all touched files are tests" };
  }
  if (paths.length && paths.every(isDocPath)) {
    return { name: "docs_only", reason: "all touched files are docs" };
  }
  if (paths.length && paths.every(isCiPath)) {
    return { name: "ci_only", reason: "all touched files are CI/config paths" };
  }
  if (isObservabilityOnlyChange(subject, runtimePaths)) {
    return { name: "observability_only", reason: "logging, metrics, stats, or counters without enforcement evidence" };
  }
  if (runtimePaths.length > 0) {
    return { name: "runtime_code_change", reason: `${runtimePaths.length} runtime files` };
  }
  return { name: "unknown_shape", reason: "no reliable file-shape metadata" };
}

function classifyReviewSecurityLocus(change, rowStats, securityScore, shape) {
  if (["merge_only", "test_only", "docs_only", "ci_only"].includes(shape.name)) {
    return { name: "suppressed_mechanical", rank: 0, reasons: [shape.name] };
  }
  if (shape.name === "observability_only") {
    return { name: "process_only_locus", rank: 1, reasons: ["observability-only change"] };
  }
  const text = reviewRiskEvidenceText(change, rowStats);
  const reasons = [];
  const serialization = /\b(pickle|unmarshal|deserialize|deserialization)\b/.test(text);
  const inputValidation = /\b(validate|validation|sanitize|bounds?|overflow|traversal|injection|xss|csrf|truncated|chunked|parser|parse|header|request body|malformed|oversized|xml|json)\b/.test(text);
  const authBoundary = /\b(auth|authentication|authorization|permission|privilege|capability|credential|secret|password|token|trust|scope|role|access)\b/.test(text);
  const dataIntegrity = /\b(checksum|digest|hash|etag|timestamp|versioning|conditional|baddigest|crc|signature|signed|encrypt|decrypt|crypto|quorum|reconstruct|replicat|corrupt)\b/.test(text);
  const stateFreshness = /\b(cache|cached|stale|expire|expiration|revoke|invalidation|cooperative|memcached|shard|ring|clock|freshness|conditional)\b/.test(text);
  const privacy = /\b(private|privacy|sensitive|leak|expos|access_user_id|credential|secret|password|token)\b/.test(text);
  const dependency = rowStats.dependencyFiles.size > 0 || /\b(requirements|dependency|package|lockfile|setup.py|pyproject)\b/.test(text);
  const workflow = rowStats.workflowFiles.size > 0 || /\b(workflow|github actions|zuul|jenkins|ci permission|pull_request_target)\b/.test(text);
  if (serialization) reasons.push("serialization");
  if (inputValidation) reasons.push("input_validation");
  if (authBoundary) reasons.push("auth_boundary");
  if (dataIntegrity) reasons.push("data_integrity");
  if (stateFreshness) reasons.push("state_freshness");
  if (privacy) reasons.push("privacy");
  if (dependency) reasons.push("dependency");
  if (workflow) reasons.push("workflow");
  const hasSecuritySurface = rowStats.securitySensitiveFiles.size > 0 || rowStats.attackSurfaceFiles.size > 0 || securityScore >= 140;
  if (serialization || ((authBoundary || inputValidation || dataIntegrity || stateFreshness) && hasSecuritySurface)) {
    return { name: "critical_locus", rank: 5, reasons };
  }
  if (authBoundary || inputValidation || dataIntegrity || stateFreshness || privacy || dependency || workflow || securityScore >= 90) {
    return { name: "important_locus", rank: 3, reasons: reasons.length ? reasons : ["moderate security score"] };
  }
  return { name: "watch", rank: 1, reasons: reasons.length ? reasons : ["weak security evidence"] };
}

function classifyReviewAuthorCompetence(authorCompetence) {
  const confidence = clamp01(numberValue(authorCompetence?.confidence));
  const competence = authorCompetence?.competence_score === null || authorCompetence?.competence_score === undefined
    ? null
    : numberValue(authorCompetence.competence_score);
  if (!authorCompetence?.has_data) {
    return { name: "thin_unknown", risk: 82, reason: "no author competence evidence" };
  }
  if (confidence < 0.35) {
    return { name: "thin_unknown", risk: 76, reason: `${Math.round(confidence * 100)}% confidence` };
  }
  if (confidence < 0.75) {
    return { name: "thin_mixed", risk: 52, reason: `${Math.round(confidence * 100)}% confidence` };
  }
  if (competence <= 55) {
    return { name: "weak_known", risk: 92, reason: `competence ${competence}/100` };
  }
  if (competence >= 78) {
    return { name: "strong_known", risk: 0, reason: `competence ${competence}/100` };
  }
  return { name: "mixed_known", risk: 34, reason: `competence ${competence}/100` };
}

function classifyReviewReviewerCompetence(reviewerHistory, participantCount, rowStats, reviewerScore) {
  const currentCount = numberValue(rowStats.approval_survival_approvals);
  const currentAvg = currentCount ? rowStats.approval_line_survival_rate_sum / currentCount : 0;
  const currentMin = currentCount ? numberValue(rowStats.min_approval_line_survival_rate) : 0;
  if (currentCount > 0) {
    if (rowStats.negative_votes > 0 || rowStats.implementation_concerns_after_positive_vote > 0 || reviewerScore >= 45) {
      return {
        name: "strong_but_struggled",
        risk: 42,
        reason: `${currentCount} current approval rows, ${roundNumber(currentAvg * 100, 1)}% survival with review friction`,
      };
    }
    if (currentAvg >= 0.92 && currentMin >= 0.75) {
      return {
        name: "strong_clean_review",
        risk: 0,
        reason: `${currentCount} current approval rows, ${roundNumber(currentAvg * 100, 1)}% avg survival`,
      };
    }
    if (currentAvg < 0.75 || rowStats.approval_cross_author_overwritten_lines > 0) {
      return {
        name: "weak_approval_survival",
        risk: 58,
        reason: `${currentCount} current approval rows, ${roundNumber(currentAvg * 100, 1)}% avg survival`,
      };
    }
    return {
      name: "mixed_review",
      risk: 24,
      reason: `${currentCount} current approval rows, ${roundNumber(currentAvg * 100, 1)}% avg survival`,
    };
  }
  const avg = reviewerHistory.length ? average(reviewerHistory.map((row) => numberValue(row.line_survival_rate))) : 0;
  const min = reviewerHistory.length ? Math.min(...reviewerHistory.map((row) => numberValue(row.line_survival_rate))) : 0;
  if (participantCount === 0 || reviewerHistory.length === 0) {
    return { name: "weak_or_missing_review", risk: 48, reason: "no reviewer survival evidence" };
  }
  if (rowStats.negative_votes > 0 || rowStats.implementation_concerns_after_positive_vote > 0 || reviewerScore >= 45) {
    return { name: "strong_but_struggled", risk: 42, reason: "review had contradiction, concern after approval, or weak survival" };
  }
  if (reviewerHistory.length >= 2 && avg >= 0.92 && min >= 0.75 && participantCount >= 2) {
    return { name: "strong_clean_review", risk: 0, reason: `${reviewerHistory.length} reviewers, ${roundNumber(avg * 100, 1)}% avg survival` };
  }
  return { name: "mixed_review", risk: 24, reason: `${reviewerHistory.length} reviewer history rows` };
}

function classifyReviewProcessSmell(rowStats, change, implementationScore, frictionScore, reworkScore) {
  const changedLines = numberValue(change.insertions) + numberValue(change.deletions);
  const highlySmelly = implementationScore >= 160
    || rowStats.patch_sets >= 16
    || rowStats.human_messages >= 50
    || numberValue(change.unresolved_comments) >= 4
    || rowStats.negative_votes > 0
    || rowStats.implementation_repeated_concern_file_count >= 2
    || rowStats.implementation_security_sensitive_repeated_concern_file_count > 0
    || rowStats.implementation_concerns_after_positive_vote >= 2;
  const smelly = highlySmelly
    || implementationScore >= 90
    || rowStats.patch_sets >= 7
    || rowStats.human_messages >= 16
    || numberValue(change.unresolved_comments) >= 2
    || rowStats.implementation_strong_concern_messages >= 2
    || rowStats.implementation_reviewer_spread_after_first_concern >= 2
    || rowStats.implementation_small_change_high_friction;
  const risk = Math.min(170, Math.round(
    implementationScore * 0.75
      + frictionScore * 0.65
      + reworkScore * 0.45
      + (rowStats.negative_votes > 0 ? 18 : 0)
      + (changedLines <= 200 && smelly ? 16 : 0),
  ));
  if (highlySmelly) return { name: "highly_smelly", risk, reason: processSmellReason(rowStats, change, implementationScore) };
  if (smelly) return { name: "smelly", risk, reason: processSmellReason(rowStats, change, implementationScore) };
  return { name: "calm", risk: Math.min(45, risk), reason: "low churn and low concern evidence" };
}

function processSmellReason(rowStats, change, implementationScore) {
  const reasons = [];
  if (implementationScore >= 90) reasons.push(`implementation ${implementationScore}`);
  if (rowStats.patch_sets >= 7) reasons.push(`${rowStats.patch_sets} patch sets`);
  if (rowStats.human_messages >= 16) reasons.push(`${rowStats.human_messages} human messages`);
  if (numberValue(change.unresolved_comments) > 0) reasons.push(`${change.unresolved_comments} unresolved`);
  if (rowStats.negative_votes > 0) reasons.push(`${rowStats.negative_votes} negative votes`);
  if (rowStats.implementation_repeated_concern_file_count > 0) reasons.push(`${rowStats.implementation_repeated_concern_file_count} repeated-concern files`);
  return reasons.join(", ") || "review friction";
}

function reviewRiskEvidenceText(change, rowStats) {
  const keywordText = (rowStats.keyword_hits || [])
    .map((hit) => `${hit.id || ""} ${hit.label || ""} ${hit.term || ""}`)
    .join(" ");
  const rawChangedFiles = Array.isArray(change.changed_files) ? change.changed_files : [];
  const pathText = (rawChangedFiles.length ? rawChangedFiles : Array.from(rowStats.touchedFiles || [])).join(" ");
  return `${change.subject || ""} ${keywordText} ${pathText}`.toLowerCase();
}

function isTestPath(path) {
  const text = String(path || "").toLowerCase();
  return /(^|\/)(test|tests|spec|specs)(\/|$)/.test(text) || /(^|\/)test_[^/]+$/.test(text) || /_test\.[a-z0-9]+$/.test(text);
}

function isDocPath(path) {
  const text = String(path || "").toLowerCase();
  return /(^|\/)(api-ref|doc|docs|documentation|releasenotes)(\/|$)/.test(text) || /\.(md|rst|txt)$/.test(text);
}

function isCiPath(path) {
  const text = String(path || "").toLowerCase();
  return /(^|\/)(\.github\/workflows|zuul|jenkins|ci|\.zuul\.yaml)(\/|$)/.test(text)
    || /(^|\/)(tox\.ini|\.pre-commit-config\.yaml|requirements.*\.txt|upper-constraints\.txt)$/.test(text);
}

function isObservabilityOnlyChange(subject, runtimePaths) {
  const text = `${subject} ${runtimePaths.join(" ")}`.toLowerCase();
  if (!/(logging|logger|metrics|stats|counter|counters|timing|\brecon\b|telemetry|observability)/.test(text)) return false;
  if (/(credential|secret|password|token|authorization|authentication|permission|privilege|encrypt|decrypt|signature|signed|private|sensitive|access_user_id|request body|auth header)/.test(text)) return false;
  return true;
}

function computeAuthorCompetence(input = {}) {
  const summary = input?.summary && typeof input.summary === "object" ? input.summary : null;
  const reviewHistory = input?.review_history && typeof input.review_history === "object" ? input.review_history : null;
  const authoredReviews = numberValue(reviewHistory?.authored_reviews_count);
  const authoredGitCommits = numberValue(input.authored_git_commits ?? summary?.authored_git_commits);
  const authoredGitChangedLines = numberValue(input.authored_git_changed_lines ?? summary?.authored_git_changed_lines);
  const hasReviewHistory = authoredReviews > 0;
  const hasGitVolume = authoredGitCommits > 0 || authoredGitChangedLines > 0;
  if (!summary && !hasReviewHistory && !hasGitVolume) {
    return {
      has_data: false,
      competence_score: null,
      risk_score: 70,
      confidence: 0,
      code_confidence: 0,
      review_confidence: 0,
      experience_confidence: 0,
      experience_score: 0,
      low_analysis_factor: 0,
      owner_author_id: String(input.owner_author_id || ""),
      owner_git_author_id: String(input.owner_git_author_id || ""),
      owner_email: String(input.owner_email || ""),
      matched_git_name: String(input.matched_git_name || ""),
      matched_git_email: String(input.matched_git_email || ""),
      match_method: String(input.match_method || ""),
      match_rank: numberValue(input.match_rank),
      line_survival_rate: 0,
      commits_analyzed: 0,
      commits_seen: 0,
      authored_git_commits: 0,
      authored_git_changed_lines: 0,
      insertions_tracked: 0,
      surviving_lines: 0,
      cross_author_overwrite_rate: 0,
      self_rework_rate: 0,
      cross_author_overwritten_lines: 0,
      self_reworked_lines: 0,
      authored_reviews_count: 0,
      merged_reviews_count: 0,
      abandoned_reviews_count: 0,
      open_reviews_count: 0,
      merged_rate: 0,
      abandoned_rate: 0,
      avg_changed_lines: 0,
      avg_patch_sets: 0,
      avg_human_messages: 0,
      avg_human_reviewers: 0,
      avg_unresolved_comments: 0,
      avg_implementation_signal_score: 0,
      avg_concern_messages: 0,
      high_implementation_reviews: 0,
      small_change_high_friction_reviews: 0,
      security_experience_reviews: 0,
      sensitive_file_reviews: 0,
    };
  }
  const lineSurvivalRate = clamp01(numberValue(summary?.line_survival_rate));
  const commitsAnalyzed = numberValue(summary?.commits_analyzed);
  const commitsSeen = numberValue(summary?.commits_seen);
  const insertionsTracked = numberValue(summary?.insertions_tracked);
  const survivingLines = numberValue(summary?.surviving_lines);
  const crossAuthorOverwriteRate = clamp01(numberValue(summary?.cross_author_overwrite_rate));
  const selfReworkRate = clamp01(numberValue(summary?.self_rework_rate));
  const codeConfidence = summary
    ? clamp01(Math.min(commitsAnalyzed / 20, insertionsTracked / 250) * 0.7 + Math.min(commitsAnalyzed / 10, 1) * 0.3)
    : 0;
  const codeRawScore = summary
    ? clampScore(
        lineSurvivalRate * 62
          + (1 - crossAuthorOverwriteRate) * 24
          + (1 - selfReworkRate) * 14,
      )
    : 60;
  const codeScore = 60 + (codeRawScore - 60) * codeConfidence;

  const mergedReviews = numberValue(reviewHistory?.merged_reviews_count);
  const abandonedReviews = numberValue(reviewHistory?.abandoned_reviews_count);
  const openReviews = numberValue(reviewHistory?.open_reviews_count);
  const mergedRate = clamp01(numberValue(reviewHistory?.merged_rate));
  const abandonedRate = clamp01(numberValue(reviewHistory?.abandoned_rate));
  const avgChangedLines = numberValue(reviewHistory?.avg_changed_lines);
  const avgPatchSets = numberValue(reviewHistory?.avg_patch_sets);
  const avgHumanMessages = numberValue(reviewHistory?.avg_human_messages);
  const avgHumanReviewers = numberValue(reviewHistory?.avg_human_reviewers);
  const avgUnresolvedComments = numberValue(reviewHistory?.avg_unresolved_comments);
  const avgImplementationSignalScore = numberValue(reviewHistory?.avg_implementation_signal_score);
  const avgConcernMessages = numberValue(reviewHistory?.avg_concern_messages);
  const highImplementationReviews = numberValue(reviewHistory?.high_implementation_reviews);
  const smallChangeHighFrictionReviews = numberValue(reviewHistory?.small_change_high_friction_reviews);
  const securityExperienceReviews = numberValue(reviewHistory?.security_experience_reviews);
  const sensitiveFileReviews = numberValue(reviewHistory?.sensitive_file_reviews);
  const reviewConfidence = hasReviewHistory ? clamp01(authoredReviews / 12) : 0;
  const highImplementationRate = authoredReviews ? highImplementationReviews / authoredReviews : 0;
  const smallHighFrictionRate = authoredReviews ? smallChangeHighFrictionReviews / authoredReviews : 0;
  const reviewRawScore = hasReviewHistory
    ? clampScore(
        78
          + Math.min(7, mergedRate * 8)
          - abandonedRate * 18
          - Math.min(22, avgImplementationSignalScore * 0.11)
          - Math.min(14, Math.max(0, avgPatchSets - 3) * 2.8)
          - Math.min(10, avgUnresolvedComments * 3.5)
          - Math.min(10, avgConcernMessages * 1.2)
          - Math.min(12, highImplementationRate * 24)
          - Math.min(10, smallHighFrictionRate * 22),
      )
    : 60;
  const reviewScore = 62 + (reviewRawScore - 62) * reviewConfidence;
  const lowAnalysisFactor = commitsAnalyzed <= 2 ? 1 : clamp01((8 - commitsAnalyzed) / 6);
  const gitCommitExperience = clamp01(authoredGitCommits / 10);
  const gitLineExperience = clamp01(authoredGitChangedLines / 4000);
  const reviewExperience = clamp01(authoredReviews / 12);
  const experienceConfidence = lowAnalysisFactor > 0
    ? clamp01(lowAnalysisFactor * (0.45 + Math.max(gitCommitExperience, gitLineExperience, reviewExperience) * 0.55))
    : 0;
  const experienceScore = clampScore(
    40
      + gitCommitExperience * 26
      + gitLineExperience * 18
      + reviewExperience * 16,
  );
  const combinedConfidence = clamp01(1 - (1 - codeConfidence) * (1 - reviewConfidence) * (1 - experienceConfidence));
  const scoreConfidence = codeConfidence + reviewConfidence + experienceConfidence;
  const weightedScore = scoreConfidence > 0
    ? (codeScore * codeConfidence + reviewScore * reviewConfidence + experienceScore * experienceConfidence) / scoreConfidence
    : 60;
  const competenceScore = Math.round(clampScore(60 + (weightedScore - 60) * Math.max(0.35, combinedConfidence)));
  const uncertaintyRisk = Math.round((1 - combinedConfidence) * 42);
  const competenceRisk = Math.round((100 - competenceScore) * (1.05 + combinedConfidence * 0.95));
  const riskScore = Math.min(reviewRiskCaps.author, Math.max(0, competenceRisk + uncertaintyRisk));
  return {
    has_data: true,
    competence_score: competenceScore,
    risk_score: riskScore,
    confidence: roundNumber(combinedConfidence, 4),
    code_confidence: roundNumber(codeConfidence, 4),
    review_confidence: roundNumber(reviewConfidence, 4),
    experience_confidence: roundNumber(experienceConfidence, 4),
    experience_score: Math.round(experienceScore),
    low_analysis_factor: roundNumber(lowAnalysisFactor, 4),
    owner_author_id: String(input.owner_author_id || ""),
    owner_git_author_id: String(input.owner_git_author_id || ""),
    owner_email: String(input.owner_email || summary?.author_email || ""),
    matched_git_name: String(input.matched_git_name || ""),
    matched_git_email: String(input.matched_git_email || ""),
    match_method: String(input.match_method || ""),
    match_rank: numberValue(input.match_rank),
    line_survival_rate: lineSurvivalRate,
    commits_analyzed: commitsAnalyzed,
    commits_seen: commitsSeen,
    authored_git_commits: authoredGitCommits,
    authored_git_changed_lines: authoredGitChangedLines,
    insertions_tracked: insertionsTracked,
    surviving_lines: survivingLines,
    cross_author_overwrite_rate: crossAuthorOverwriteRate,
    self_rework_rate: selfReworkRate,
    cross_author_overwritten_lines: numberValue(summary?.cross_author_overwritten_lines),
    self_reworked_lines: numberValue(summary?.self_reworked_lines),
    authored_reviews_count: authoredReviews,
    merged_reviews_count: mergedReviews,
    abandoned_reviews_count: abandonedReviews,
    open_reviews_count: openReviews,
    merged_rate: mergedRate,
    abandoned_rate: abandonedRate,
    avg_changed_lines: avgChangedLines,
    avg_patch_sets: avgPatchSets,
    avg_human_messages: avgHumanMessages,
    avg_human_reviewers: avgHumanReviewers,
    avg_unresolved_comments: avgUnresolvedComments,
    avg_implementation_signal_score: avgImplementationSignalScore,
    avg_concern_messages: avgConcernMessages,
    high_implementation_reviews: highImplementationReviews,
    small_change_high_friction_reviews: smallChangeHighFrictionReviews,
    security_experience_reviews: securityExperienceReviews,
    sensitive_file_reviews: sensitiveFileReviews,
  };
}

function scoreContributorBuckets(rowStats, context) {
  return [
    {
      bucket: "Mission priority",
      points: context.missionPriority?.score || 0,
      items: [
        { label: "Priority lane", value: context.missionPriority?.priority_lane || "watch" },
        { label: "Security locus", value: context.missionPriority?.security_locus || "watch" },
        { label: "Change shape", value: context.missionPriority?.change_shape || "unknown" },
        { label: "Author bucket", value: context.missionPriority?.author_bucket || "unknown" },
        { label: "Reviewer bucket", value: context.missionPriority?.reviewer_bucket || "unknown" },
        { label: "Process bucket", value: context.missionPriority?.process_bucket || "unknown" },
        { label: "Legacy flat score", value: context.flatRiskScore || 0 },
      ],
    },
    {
      bucket: "Security",
      points: context.securityScore,
      items: [
        { label: "Keyword score", value: rowStats.keyword_weighted_score, points: Math.min(rowStats.keyword_weighted_score, keywordScoreCap) },
        { label: "Keyword kinds", value: context.distinctSignalKinds, points: context.distinctSignalKinds * 8 },
        { label: "ONNX weighted score", value: rowStats.sensitivity_weighted_score, points: rowStats.sensitivity_weighted_score },
        { label: "Security-sensitive files", value: rowStats.securitySensitiveFiles.size, points: rowStats.securitySensitiveFiles.size * 28 },
        { label: "Attack-surface files", value: rowStats.attackSurfaceFiles.size, points: rowStats.attackSurfaceFiles.size * 22 },
        { label: "Dependency files", value: rowStats.dependencyFiles.size, points: rowStats.dependencyFiles.size * 16 },
        { label: "Workflow/CI files", value: rowStats.workflowFiles.size, points: rowStats.workflowFiles.size * 16 },
      ],
    },
    {
      bucket: "Author competence",
      points: context.authorScore,
      items: [
        { label: "Competence score", value: context.authorCompetence.competence_score ?? "unknown" },
        { label: "Overall confidence", value: roundNumber(context.authorCompetence.confidence * 100, 1), unit: "%" },
        { label: "Code evidence confidence", value: roundNumber(context.authorCompetence.code_confidence * 100, 1), unit: "%" },
        { label: "Review history confidence", value: roundNumber(context.authorCompetence.review_confidence * 100, 1), unit: "%" },
        { label: "Experience confidence", value: roundNumber(context.authorCompetence.experience_confidence * 100, 1), unit: "%" },
        { label: "Experience score", value: context.authorCompetence.experience_score },
        { label: "Low line-survival-analysis factor", value: roundNumber(context.authorCompetence.low_analysis_factor * 100, 1), unit: "%" },
        { label: "Authored git commits", value: context.authorCompetence.authored_git_commits },
        { label: "Authored git changed lines", value: context.authorCompetence.authored_git_changed_lines },
        { label: "Authored reviews", value: context.authorCompetence.authored_reviews_count },
        { label: "Merged reviews", value: context.authorCompetence.merged_reviews_count },
        { label: "Abandoned reviews", value: context.authorCompetence.abandoned_reviews_count },
        { label: "Avg historical implementation score", value: roundNumber(context.authorCompetence.avg_implementation_signal_score, 1) },
        { label: "Avg historical patch sets", value: roundNumber(context.authorCompetence.avg_patch_sets, 2) },
        { label: "Avg unresolved comments", value: roundNumber(context.authorCompetence.avg_unresolved_comments, 2) },
        { label: "High-implementation-risk reviews", value: context.authorCompetence.high_implementation_reviews },
        { label: "Small high-friction reviews", value: context.authorCompetence.small_change_high_friction_reviews },
        { label: "Line survival", value: roundNumber(context.authorCompetence.line_survival_rate * 100, 1), unit: "%" },
        { label: "Commits analyzed", value: context.authorCompetence.commits_analyzed },
        { label: "Tracked insertions", value: context.authorCompetence.insertions_tracked },
        { label: "Cross-author overwrite rate", value: roundNumber(context.authorCompetence.cross_author_overwrite_rate * 100, 1), unit: "%" },
        { label: "Self rework rate", value: roundNumber(context.authorCompetence.self_rework_rate * 100, 1), unit: "%" },
        { label: "Identity match", value: context.authorCompetence.match_method || "none" },
        { label: "Matched Git email", value: context.authorCompetence.matched_git_email || "" },
      ],
    },
    {
      bucket: "Reviewer survival",
      points: context.reviewerScore,
      items: [
        { label: "Current approval survival rows", value: rowStats.approval_survival_approvals, points: rowStats.approval_survival_approvals > 0 ? Math.round((1 - context.approvalAvg) * 90) : 0 },
        { label: "Current approval avg survival", value: roundNumber(context.approvalAvg * 100, 1), unit: "%" },
        { label: "Current approval overwritten lines", value: rowStats.approval_cross_author_overwritten_lines, points: Math.min(30, rowStats.approval_cross_author_overwritten_lines * 3) },
        { label: "Reviewer history rows", value: context.reviewerHistory.length, points: rowStats.approval_survival_approvals === 0 && context.reviewerHistory.length > 0 ? Math.round((1 - context.reviewerAvg) * 80) : 0 },
        { label: "Reviewer history avg survival", value: roundNumber(context.reviewerAvg * 100, 1), unit: "%" },
      ],
      approval_survival_reviewers: rowStats.approval_survival_reviewers,
      reviewer_history: context.reviewerHistory,
    },
    {
      bucket: "Implementation risk",
      points: context.implementationScore,
      items: context.implementationBreakdown.items,
    },
    {
      bucket: "Friction",
      points: context.frictionScore,
      items: [
        { label: "Unresolved comments", value: numberValue(context.change.unresolved_comments), points: numberValue(context.change.unresolved_comments) * 10 },
        { label: "Negative votes", value: rowStats.negative_votes, points: rowStats.negative_votes * 16 },
        { label: "Contradicted votes", value: Math.min(rowStats.positive_votes, rowStats.negative_votes), points: Math.min(rowStats.positive_votes, rowStats.negative_votes) * 24 },
        { label: "Comment volume", value: numberValue(context.change.total_comments), points: Math.round(Math.sqrt(Math.max(numberValue(context.change.total_comments), 0)) * 5) },
        { label: "Reviewers after first concern", value: rowStats.implementation_reviewer_spread_after_first_concern, points: Math.min(14, rowStats.implementation_reviewer_spread_after_first_concern * 3) },
        { label: "Patch sets with concerns", value: rowStats.implementation_distinct_concern_patch_sets, points: Math.min(10, rowStats.implementation_distinct_concern_patch_sets * 2) },
        { label: "Small change high friction", value: rowStats.implementation_small_change_high_friction ? "yes" : "no", points: rowStats.implementation_small_change_high_friction ? 10 : 0 },
      ],
    },
    {
      bucket: "Rework",
      points: context.reworkScore,
      items: [
        { label: "Patch sets", value: rowStats.patch_sets, points: Math.round(rowStats.patch_sets * 1.5) },
        { label: "Touched files", value: rowStats.touchedFiles.size, points: Math.round(rowStats.touchedFiles.size * 1.25) },
        { label: "Human reviewers", value: context.participantCount, points: context.participantCount * 2 },
        { label: "Patch sets after first concern", value: rowStats.implementation_patch_sets_after_first_concern, points: Math.min(12, rowStats.implementation_patch_sets_after_first_concern * 2) },
        { label: "Concern span across patch sets", value: rowStats.implementation_concern_span_patch_sets, points: Math.min(8, rowStats.implementation_concern_span_patch_sets * 2) },
      ],
    },
    {
      bucket: "Changed lines",
      points: context.changedLinesScore,
      items: [
        {
          label: "Lines changed",
          value: numberValue(context.change.insertions) + numberValue(context.change.deletions),
          points: context.changedLinesScore,
        },
      ],
    },
    {
      bucket: "Stale",
      points: context.staleScore,
      items: [{ label: "Age days", value: context.ageDays, points: context.staleScore }],
    },
  ];
}

function reviewRiskScoreItems(context = {}) {
  const rowStats = context.rowStats || emptyReviewRiskStats();
  const fileSurfaceScore = rowStats.securitySensitiveFiles.size * 28
    + rowStats.attackSurfaceFiles.size * 22
    + rowStats.dependencyFiles.size * 16
    + rowStats.workflowFiles.size * 16;
  const keywordScore = Math.min(rowStats.keyword_weighted_score, keywordScoreCap)
    + numberValue(context.distinctSignalKinds) * 8
    + rowStats.security_scenario_hits * 3;
  return [
    {
      score_id: "security_keyword_score",
      score: clampScore(keywordScore),
      confidence: 1,
      weight: 1.4,
    },
    {
      score_id: "security_sensitivity_score",
      score: clampScore(rowStats.sensitivity_weighted_score),
      confidence: rowStats.sensitivityScores.length ? 1 : 0.7,
      weight: 1.0,
    },
    {
      score_id: "security_file_surface_score",
      score: clampScore(fileSurfaceScore),
      confidence: 1,
      weight: 1.2,
    },
    {
      score_id: "author_competence_score",
      score: clampScore(context.authorScore),
      confidence: Math.max(0.2, numberValue(context.authorCompetence?.confidence)),
      weight: 1.3,
    },
    {
      score_id: "reviewer_survival_score",
      score: clampScore(context.reviewerScore),
      confidence: rowStats.approval_survival_approvals > 0 ? 1 : 0.7,
      weight: 1.1,
    },
    {
      score_id: "implementation_concern_score",
      score: clampScore(context.implementationScore),
      confidence: 1,
      weight: 1.5,
    },
    {
      score_id: "review_friction_score",
      score: clampScore(context.frictionScore),
      confidence: 1,
      weight: 1.0,
    },
    {
      score_id: "review_churn_score",
      score: clampScore(context.reworkScore),
      confidence: 1,
      weight: 0.8,
    },
    {
      score_id: "changed_lines_score",
      score: clampScore(context.changedLinesScore),
      confidence: 1,
      weight: 0.9,
    },
    {
      score_id: "staleness_score",
      score: clampScore(context.staleScore),
      confidence: 1,
      weight: 0.3,
    },
  ];
}

function reviewRiskWeightedBucketScore(items = []) {
  let weightedSum = 0;
  let denominator = 0;
  const scoredItems = items.map((item) => {
    const score = clampScore(item.score);
    const weight = Math.max(0, numberValue(item.weight || 1));
    const confidence = clamp01(item.confidence === undefined ? 1 : item.confidence);
    const effectiveWeight = weight * confidence;
    const weightedValue = score * effectiveWeight;
    weightedSum += weightedValue;
    denominator += effectiveWeight;
    return {
      ...item,
      score,
      confidence: roundNumber(confidence, 4),
      details: {
        weight,
        effective_weight: roundNumber(effectiveWeight, 4),
        weighted_value: roundNumber(weightedValue, 4),
      },
    };
  });
  return {
    score_bucket_id: "review_risk_weighted_average",
    score: denominator > 0 ? roundNumber(weightedSum / denominator, 4) : 0,
    aggregation: "weighted_average",
    items: scoredItems,
    denominator: roundNumber(denominator, 4),
    details: {
      weighted_sum: roundNumber(weightedSum, 4),
      version: "review_risk_v1",
      formula: "sum(score * weight * confidence) / sum(weight * confidence)",
    },
  };
}

function reviewRiskResponseSkeleton(options, normalizedStatus, since, until, dateField, limit, keywordRepositoryId, keywordConfig) {
  return {
    generated_at: new Date().toISOString(),
    filters: {
      repository_id: options.repositoryId || "",
      project: options.project || "",
      status: normalizedStatus,
      month: options.month || "",
      since: since || "",
      until: until || "",
      date_field: dateField,
      limit,
      keyword_repository_id: keywordRepositoryId,
    },
    keyword_config: keywordConfig,
    review_risk_weights: reviewRiskWeights(),
    review_risk_summary: {
      proposed_reviews: 0,
      critical_reviews: 0,
      high_reviews: 0,
      avg_risk_score: 0,
      max_risk_score: 0,
      avg_bucket_score: 0,
      max_bucket_score: 0,
    },
    proposed_review_risk: [],
  };
}

function reviewRiskWeights() {
  return [
    { bucket: "Mission priority", field: "security_locus", weight: "gate only; does not dominate final ranking" },
    { bucket: "Mission priority", field: "author_competence_bucket", weight: "decisive inside security-relevant reviews" },
    { bucket: "Mission priority", field: "reviewer_competence_bucket", weight: "decisive when review evidence is weak or struggled" },
    { bucket: "Mission priority", field: "process_smell_bucket", weight: "implementation smell, churn, friction decide escalation" },
    { bucket: "Mission priority", field: "change_shape", weight: "suppresses merge/test/docs/CI-only; separates observability-only" },
    { bucket: "Security", field: "configured_keyword_weight_sum_capped_at_160", weight: "per keyword config" },
    { bucket: "Security", field: "distinct_rule_keyword_kinds", weight: 8 },
    { bucket: "Security", field: "onnx_40_to_54", weight: 8 },
    { bucket: "Security", field: "onnx_55_to_69", weight: 18 },
    { bucket: "Security", field: "onnx_70_plus", weight: 40 },
    { bucket: "Security", field: "security_sensitive_files", weight: 28 },
    { bucket: "Security", field: "attack_surface_files", weight: 22 },
    { bucket: "Security", field: "dependency_files", weight: 16 },
    { bucket: "Security", field: "workflow_files", weight: 16 },
    { bucket: "Author competence", field: "git_line_survival_and_rework", weight: "confidence weighted" },
    { bucket: "Author competence", field: "historical_review_quality", weight: "confidence weighted" },
    { bucket: "Author competence", field: "uncertainty", weight: "up to 42" },
    { bucket: "Author competence", field: "low_confidence_low_competence", weight: "bucket cap 220" },
    { bucket: "Reviewer survival", field: "current_approval_avg_survival_gap", weight: "up to 90, bucket cap 100" },
    { bucket: "Reviewer survival", field: "current_approval_overwritten_lines", weight: "3 each, cap 30" },
    { bucket: "Reviewer survival", field: "reviewer_history_avg_survival_gap", weight: "up to 80" },
    { bucket: "Implementation risk", field: "strong_concern_score", weight: "2x weighted strong concern vocabulary, cap 72" },
    { bucket: "Implementation risk", field: "file_specific_strong_concerns", weight: "10 each, cap 34" },
    { bucket: "Implementation risk", field: "repeated_concern_file_count", weight: "12 each, cap 36" },
    { bucket: "Implementation risk", field: "security_sensitive_repeated_concern_file_count", weight: "24 each, cap 48" },
    { bucket: "Implementation risk", field: "concerns_after_positive_vote", weight: "8 each, cap 28" },
    { bucket: "Implementation risk", field: "concern_density_per_touched_file", weight: "8 per density point, cap 24" },
    { bucket: "Implementation risk", field: "strong_concern_categories", weight: "6 each, cap 18" },
    { bucket: "Implementation risk", field: "author_response_ratio_after_strong_concerns", weight: "10 when >=40% with at least 2 strong concern messages" },
    { bucket: "Implementation risk", field: "aggregate_fallback_when_no_strong_concerns", weight: "35% of aggregate score, cap 30" },
    { bucket: "Friction", field: "unresolved_comments", weight: "10 each, bucket cap 80" },
    { bucket: "Friction", field: "negative_votes", weight: 16 },
    { bucket: "Friction", field: "contradicted_votes", weight: 24 },
    { bucket: "Friction", field: "reviewers_after_first_concern", weight: "3 each, cap 14" },
    { bucket: "Friction", field: "distinct_concern_patch_sets", weight: "2 each, cap 10" },
    { bucket: "Friction", field: "small_change_high_friction", weight: 10 },
    { bucket: "Rework", field: "patch_sets", weight: "1.5 each, bucket cap 50" },
    { bucket: "Rework", field: "touched_files", weight: "1.25 each" },
    { bucket: "Rework", field: "human_reviewers", weight: 2 },
    { bucket: "Rework", field: "patch_sets_after_first_concern", weight: "2 each, cap 12" },
    { bucket: "Rework", field: "concern_span_patch_sets", weight: "2 each, cap 8" },
    { bucket: "Changed lines", field: "changed_lines_score", weight: "bracketed 0-100 score from insertions + deletions" },
    { bucket: "Stale", field: "days_open_after_30", weight: "1 per 14 days, bucket cap 30" },
  ];
}

function compileKeywordRules(rules = []) {
  return (rules || []).filter((rule) => rule.enabled !== false && rule.pattern).map((rule) => {
    try {
      return { ...rule, regex: new RegExp(rule.pattern, "i") };
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function distinctKeywordHits(hits = []) {
  const byId = new Map();
  for (const hit of hits || []) {
    if (!hit?.id || byId.has(hit.id)) continue;
    byId.set(hit.id, hit);
  }
  return Array.from(byId.values()).sort((left, right) =>
    numberValue(left.order) - numberValue(right.order) || String(left.label || "").localeCompare(String(right.label || ""))
  );
}

function queryJsonArray(sql) {
  return runPsqlJson(sql).then((value) => Array.isArray(value) ? value : []);
}

function sqlInList(values = []) {
  const unique = uniqueStrings(values);
  if (!unique.length) return "''";
  return unique.map(sqlLiteral).join(",");
}

function uniqueStrings(values = []) {
  return Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)));
}

function displayAuthorName(authorsById, authorId) {
  const author = authorsById.get(String(authorId || ""));
  return String(author?.display_name || authorId || "");
}

function stringValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return String(value);
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function clamp01(value) {
  return Math.max(0, Math.min(1, numberValue(value)));
}

function clampScore(value) {
  return Math.max(0, Math.min(100, numberValue(value)));
}

function changedLinesRiskScore(lines) {
  const changedLines = Math.max(0, Math.round(numberValue(lines)));
  if (changedLines === 0) return 0;
  if (changedLines <= 10) return 5;
  if (changedLines <= 25) return 12;
  if (changedLines <= 50) return 20;
  if (changedLines <= 100) return 32;
  if (changedLines <= 250) return 48;
  if (changedLines <= 500) return 62;
  if (changedLines <= 1000) return 76;
  if (changedLines <= 2500) return 90;
  return 100;
}

function average(values = []) {
  const nums = values.map(numberValue).filter((value) => Number.isFinite(value));
  if (!nums.length) return 0;
  return nums.reduce((sum, value) => sum + value, 0) / nums.length;
}

function roundNumber(value, digits = 0) {
  const factor = 10 ** digits;
  return Math.round(numberValue(value) * factor) / factor;
}

function ageDaysFromTimestamp(value) {
  const text = String(value || "");
  if (!text) return 0;
  const millis = Date.parse(text.endsWith("Z") ? text : `${text}Z`);
  if (!Number.isFinite(millis)) return 0;
  return Math.max(0, Math.floor((Date.now() - millis) / 86400000));
}

function isDependencyPath(path) {
  const lower = String(path || "").toLowerCase();
  return lower.includes("requirements")
    || lower.includes("package.json")
    || lower.includes("setup.py")
    || lower.includes("setup.cfg")
    || lower.includes("pyproject.toml")
    || lower.includes("tox.ini");
}

function isWorkflowPath(path) {
  const lower = String(path || "").toLowerCase();
  return lower.includes(".github/workflows")
    || lower.includes("zuul")
    || lower.includes("jenkins")
    || lower.includes("tox.ini");
}

async function queryRepointelReviewRiskMessages(options = {}) {
  const changeNumber = String(options.changeNumber || "").trim();
  if (!changeNumber) {
    return {
      change_number: "",
      project: options.project || "",
      min_score: Math.max(0, Number(options.minScore || 40)),
      messages: [],
    };
  }
  const minScore = Math.max(0, Number(options.minScore || 40));
  const keywordRepositoryId = await resolveKeywordRepositoryId(options);
  const keywordConfig = await getKeywordConfig(keywordRepositoryId);
  const keywordRulesSql = keywordRulesValuesSql(keywordConfig.rules);
  const rawFilters = [
    "collection = 'raw-records'",
    "doc->>'record_type' = 'gerrit_change'",
    `doc->'payload'->>'_number' = ${sqlLiteral(changeNumber)}`,
  ];
  if (options.project) {
    rawFilters.push(`coalesce(nullif(doc->'payload'->>'project', ''), '') = ${sqlLiteral(options.project)}`);
  }
  if (options.repositoryId) {
    rawFilters.push(`doc->>'repository_id' = ${sqlLiteral(options.repositoryId)}`);
  }
  const sql = `
    with
    keyword_rules(id, label, pattern, color, weight, display_order, enabled) as (
      ${keywordRulesSql}
    ),
    change_rows as (
      select
        doc->>'repository_id' as repository_id,
        doc->'payload'->>'_number' as change_number,
        coalesce(nullif(doc->'payload'->>'project', ''), '') as project,
        coalesce(nullif(doc->'payload'->>'subject', ''), '') as subject,
        coalesce(doc->>'url', '') as review_url
      from repointel_records
      where ${rawFilters.join("\n        and ")}
      limit 1
    ),
    art_messages as (
      select
        a.id as art_id,
        a.doc->>'author_id' as author_id,
        coalesce(au.doc->>'display_name', au.doc->>'name', a.doc->>'author_id', '') as author,
        coalesce(a.doc->>'source_created_at', a.doc->>'created_at', a.doc->>'imported_at', '') as created_at,
        coalesce(nullif(a.doc->>'patch_set', ''), '') as patch_set,
        coalesce(a.doc->>'body', '') as body,
        round(coalesce((m.doc->'value'->>'score')::numeric, 0), 2) as score,
        coalesce(m.doc->'value'->>'label', '') as label,
        coalesce(m.doc->'value'->>'model', '') as model,
        coalesce(m.doc->'value'->>'text_preview', left(coalesce(a.doc->>'body', ''), 240)) as text_preview,
        exists (
          select 1
          from keyword_rules kr
          where kr.enabled = true
            and coalesce(a.doc->>'body', '') ~* kr.pattern
        ) as keyword_hit,
        coalesce((
          select jsonb_agg(jsonb_build_object(
            'id', kr.id,
            'label', kr.label,
            'pattern', kr.pattern,
            'color', kr.color,
            'weight', kr.weight,
            'order', kr.display_order,
            'enabled', kr.enabled
          ) order by kr.display_order, kr.label)
          from keyword_rules kr
          where kr.enabled = true
            and coalesce(a.doc->>'body', '') ~* kr.pattern
        ), '[]'::jsonb) as keyword_matches,
        coalesce((
          select sum(kr.weight)::bigint
          from keyword_rules kr
          where kr.enabled = true
            and coalesce(a.doc->>'body', '') ~* kr.pattern
        ), 0)::bigint as keyword_weight_sum,
        coalesce((
          select count(*)::bigint
          from keyword_rules kr
          where kr.enabled = true
            and coalesce(a.doc->>'body', '') ~* kr.pattern
        ), 0)::bigint as keyword_match_count
      from repointel_records a
      join change_rows c on c.change_number = a.doc->>'context_external_id'
      left join repointel_records m
        on m.collection = 'metadata'
       and m.doc->>'subject_type' = 'art'
       and m.doc->>'subject_id' = a.id
       and m.doc->>'namespace' = 'security.sensitivity'
       and m.doc->>'key' = 'score'
      left join repointel_records au
        on au.collection = 'authors'
       and au.id = a.doc->>'author_id'
      where a.collection = 'arts'
        and a.doc->>'type' = 'code_review_message'
    ),
    scored_messages as (
      select
        *,
        round((coalesce(score, 0) + coalesce(keyword_weight_sum, 0))::numeric, 2) as combined_score
      from art_messages
      where score >= ${minScore}
         or keyword_hit = true
      order by combined_score desc, score desc, keyword_weight_sum desc, art_id
    )
    select jsonb_build_object(
      'change_number', ${sqlLiteral(changeNumber)},
      'project', coalesce((select project from change_rows), ${sqlLiteral(options.project || "")}),
      'repository_id', coalesce((select repository_id from change_rows), ${sqlLiteral(options.repositoryId || "")}),
      'keyword_repository_id', ${sqlLiteral(keywordRepositoryId)},
      'keyword_config', ${sqlLiteral(JSON.stringify(keywordConfig))}::jsonb,
      'subject', coalesce((select subject from change_rows), ''),
      'review_url', coalesce((select review_url from change_rows), ''),
      'min_score', ${minScore},
      'count', (select count(*)::bigint from scored_messages),
      'messages', coalesce((
        select jsonb_agg(to_jsonb(scored_messages) order by combined_score desc, score desc, keyword_weight_sum desc, art_id)
        from scored_messages
      ), '[]'::jsonb)
    )::text;
  `;
  return runPsqlJson(sql);
}

async function getKeywordConfig(repositoryId = "") {
  const normalizedRepositoryId = String(repositoryId || "").trim();
  return metadataCollectionJson("POST", "/keyword-configs:resolve", {
    repository_id: normalizedRepositoryId,
  });
}

function normalizeKeywordRules(rules = []) {
  return (rules || [])
    .map(normalizeKeywordRule)
    .filter((rule) => rule.id && rule.pattern)
    .sort((left, right) => Number(left.order || 0) - Number(right.order || 0) || left.label.localeCompare(right.label));
}

function normalizeKeywordRule(rule = {}) {
  return {
    id: String(rule.id || "").trim(),
    label: String(rule.label || rule.id || "").trim(),
    pattern: String(rule.pattern || "").trim(),
    color: /^#[0-9a-f]{6}$/i.test(String(rule.color || "")) ? String(rule.color) : "#245da8",
    weight: Math.max(0, Math.min(100, Number.parseInt(String(rule.weight ?? 0), 10) || 0)),
    order: Number.parseInt(String(rule.order ?? 0), 10) || 0,
    enabled: rule.enabled !== false,
  };
}

function keywordRulesValuesSql(rules = []) {
  const normalized = normalizeKeywordRules(rules);
  if (!normalized.length) {
    return `select ''::text as id, ''::text as label, 'a^'::text as pattern, '#245da8'::text as color, 0::int as weight, 0::int as display_order, false::boolean as enabled`;
  }
  return `
    values ${normalized.map((rule) => `(
      ${sqlLiteral(rule.id)},
      ${sqlLiteral(rule.label)},
      ${sqlLiteral(rule.pattern)},
      ${sqlLiteral(rule.color)},
      ${Number(rule.weight || 0)}::int,
      ${Number(rule.order || 0)}::int,
      ${rule.enabled ? "true" : "false"}::boolean
    )`).join(",")}
  `;
}

async function resolveKeywordRepositoryId(options = {}) {
  if (options.repositoryId) return String(options.repositoryId);
  if (!options.project) return "";
  const sql = `
    select to_json(coalesce((
      select doc->>'repository_id'
      from repointel_records
      where collection = 'raw-records'
        and doc->>'record_type' = 'gerrit_change'
        and coalesce(nullif(doc->'payload'->>'project', ''), '') = ${sqlLiteral(options.project)}
        and coalesce(doc->>'repository_id', '') <> ''
      limit 1
    ), ''))::text;
  `;
  const value = await runPsqlJson(sql);
  return typeof value === "string" ? value : "";
}

function runPsqlJson(sql) {
  return new Promise((resolve, reject) => {
    const child = spawn("psql", ["-X", "-q", "-t", "-A", repointelDatabaseUrl], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdin.end(sql);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `psql exited with ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim() || "{}"));
      } catch (err) {
        reject(new Error(`Could not parse analytics JSON: ${err.message}`));
      }
    });
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function metadataCollectionJson(method, path, body) {
  const token = firstEnv(["METADATA_COLLECTION_GATEWAY_TOKEN", "METADATA_COLLECTION_TOKEN"]);
  if (!token) {
    throw new Error("Set METADATA_COLLECTION_GATEWAY_TOKEN or METADATA_COLLECTION_TOKEN for analytics provider metadata calls.");
  }
  const upstream = await fetch(`${collectionBase}/metadata-collection${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await upstream.text();
  const value = text ? JSON.parse(text) : null;
  if (!upstream.ok) {
    throw new Error(value?.message || value?.error || `${method} ${path} failed with ${upstream.status}`);
  }
  return value;
}

function stripSlash(value) {
  return value.replace(/\/+$/, "");
}

function firstEnv(names) {
  for (const name of names) {
    const value = String(process.env[name] || "").trim();
    if (value) return value;
  }
  return "";
}

function authorizedProviderRequest(req, expectedToken) {
  const token = bearerToken(req.headers.authorization || "");
  return Boolean(expectedToken) && constantTimeEqual(token, expectedToken);
}

function bearerToken(value) {
  const text = String(value || "").trim();
  return text.toLowerCase().startsWith("bearer ") ? text.slice(7).trim() : "";
}

function constantTimeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ""));
  const rightBuffer = Buffer.from(String(right || ""));
  const maxLength = Math.max(leftBuffer.length, rightBuffer.length);
  let diff = leftBuffer.length ^ rightBuffer.length;
  for (let index = 0; index < maxLength; index += 1) {
    diff |= (leftBuffer[index] || 0) ^ (rightBuffer[index] || 0);
  }
  return diff === 0;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : fallback;
}

function parseBooleanParam(value, fallback = false) {
  if (value === null || value === undefined || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function hasAuthorHistoryIdentity(options = {}) {
  return [
    options.q,
    options.name,
    options.lastName,
    options.email,
    options.authorId,
    options.externalAuthorId,
    options.gerritAccountId,
    options.changeNumber,
  ].some((value) => String(value || "").trim() !== "");
}

function monthToRange(month) {
  const match = String(month || "").match(/^(\d{4})-(\d{2})$/);
  if (!match) return { since: "", until: "" };
  const year = Number(match[1]);
  const monthIndex = Number(match[2]);
  if (!Number.isInteger(year) || !Number.isInteger(monthIndex) || monthIndex < 1 || monthIndex > 12) {
    return { since: "", until: "" };
  }
  const since = `${String(year).padStart(4, "0")}-${String(monthIndex).padStart(2, "0")}-01`;
  const untilDate = new Date(Date.UTC(year, monthIndex, 1));
  const until = `${untilDate.getUTCFullYear()}-${String(untilDate.getUTCMonth() + 1).padStart(2, "0")}-01`;
  return { since, until };
}

function sqlLiteral(value) {
  return `'${String(value ?? "").replaceAll("'", "''")}'`;
}

function writeJson(res, status, value, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...securityHeaders(),
    ...headers,
  });
  res.end(JSON.stringify(value));
}

function json(res, value, headers = {}) {
  writeJson(res, 200, value, headers);
}

function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "same-origin",
  };
}
