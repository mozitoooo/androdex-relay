const { createHash, createPublicKey, verify } = require("crypto");
const { WebSocket } = require("ws");

const CLEANUP_DELAY_MS = 60_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const HOST_ABSENCE_GRACE_MS = 15_000;

const CLOSE_CODE_INVALID = 4000;
const CLOSE_CODE_HOST_REPLACED = 4001;
const CLOSE_CODE_SESSION_UNAVAILABLE = 4002;
const CLOSE_CODE_ANDROID_REPLACED = 4003;
const CLOSE_CODE_HOST_MISSING = 4004;

const TRUSTED_SESSION_RESOLVE_TAG = "androdex-trusted-session-resolve-v1";
const TRUSTED_SESSION_RESOLVE_SKEW_MS = 90_000;

const sessions = new Map();
const liveSessionsByHostDeviceId = new Map();
const usedResolveNonces = new Map();

function setupRelay(
  wss,
  {
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
    hostAbsenceGraceMs = HOST_ABSENCE_GRACE_MS,
  } = {}
) {
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws._relayAlive === false) {
        ws.terminate();
        continue;
      }
      ws._relayAlive = false;
      ws.ping();
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeat.unref?.();

  wss.on("close", () => clearInterval(heartbeat));

  wss.on("connection", (ws, req) => {
    const path = req.url || "";
    const match = path.match(/^\/relay\/([^/?#]+)/);
    const sessionId = match?.[1];
    const role = resolveConnectionRole(req);

    if (!sessionId || (role !== "host" && role !== "android")) {
      ws.close(CLOSE_CODE_INVALID, "Missing session or invalid role");
      return;
    }

    ws._relayAlive = true;
    ws.on("pong", () => {
      ws._relayAlive = true;
    });

    if (role === "android" && !sessions.has(sessionId)) {
      ws.close(CLOSE_CODE_SESSION_UNAVAILABLE, "Host session not available");
      return;
    }

    if (!sessions.has(sessionId)) {
      sessions.set(sessionId, createSessionRecord());
    }
    const session = sessions.get(sessionId);

    if (role === "android" && !canAcceptAndroidConnection(session)) {
      ws.close(CLOSE_CODE_SESSION_UNAVAILABLE, "Host session not available");
      return;
    }

    if (session.cleanupTimer) {
      clearTimeoutFn(session.cleanupTimer);
      session.cleanupTimer = null;
    }

    if (role === "host") {
      clearHostAbsenceTimer(session, { clearTimeoutFn });
      session.notificationSecret = readHeaderString(req.headers["x-notification-secret"]) || null;
      session.hostRegistration = readHostRegistrationHeaders(req.headers, sessionId);
      if (session.host && session.host.readyState === WebSocket.OPEN) {
        session.host.close(CLOSE_CODE_HOST_REPLACED, "Replaced by new host connection");
      }
      session.host = ws;
      registerLiveHostSession(session.hostRegistration);
      console.log(`[relay] host connected -> ${relaySessionLogLabel(sessionId)}`);
    } else {
      if (session.android && session.android.readyState === WebSocket.OPEN) {
        session.android.close(CLOSE_CODE_ANDROID_REPLACED, "Replaced by newer Android connection");
      }
      session.android = ws;
      console.log(`[relay] android connected -> ${relaySessionLogLabel(sessionId)}`);
    }

    ws.on("message", (data) => {
      const message = typeof data === "string" ? data : data.toString("utf8");
      if (role === "host" && applyHostRegistrationMessage(session, sessionId, message)) {
        return;
      }

      if (role === "host") {
        if (session.android?.readyState === WebSocket.OPEN) {
          session.android.send(message);
        }
        return;
      }

      if (session.host?.readyState === WebSocket.OPEN) {
        session.host.send(message);
      } else {
        ws.close(CLOSE_CODE_HOST_MISSING, "Host temporarily unavailable");
      }
    });

    ws.on("close", () => {
      if (role === "host") {
        if (session.host === ws) {
          session.host = null;
          unregisterLiveHostSession(session.hostRegistration, sessionId);
          console.log(`[relay] host disconnected -> ${relaySessionLogLabel(sessionId)}`);
          if (session.android) {
            scheduleHostAbsenceTimeout(sessionId, {
              hostAbsenceGraceMs,
              setTimeoutFn,
              clearTimeoutFn,
            });
          } else {
            scheduleCleanup(sessionId, { setTimeoutFn });
          }
        }
      } else if (session.android === ws) {
        session.android = null;
        console.log(`[relay] android disconnected -> ${relaySessionLogLabel(sessionId)}`);
        scheduleCleanup(sessionId, { setTimeoutFn });
      }
    });

    ws.on("error", (error) => {
      console.error(`[relay] websocket error (${role}, ${relaySessionLogLabel(sessionId)}): ${error.message}`);
    });
  });
}

function createSessionRecord() {
  return {
    host: null,
    android: null,
    hostRegistration: null,
    notificationSecret: null,
    cleanupTimer: null,
    hostAbsenceTimer: null,
  };
}

function scheduleCleanup(sessionId, { setTimeoutFn = setTimeout } = {}) {
  const session = sessions.get(sessionId);
  if (!session) {
    return;
  }
  if (session.cleanupTimer || session.host || session.android || session.hostAbsenceTimer) {
    return;
  }

  session.cleanupTimer = setTimeoutFn(() => {
    const active = sessions.get(sessionId);
    if (!active) {
      return;
    }
    if (active.host || active.android || active.hostAbsenceTimer) {
      active.cleanupTimer = null;
      return;
    }
    unregisterLiveHostSession(active.hostRegistration, sessionId);
    sessions.delete(sessionId);
    console.log(`[relay] cleaned -> ${relaySessionLogLabel(sessionId)}`);
  }, CLEANUP_DELAY_MS);
  session.cleanupTimer.unref?.();
}

function scheduleHostAbsenceTimeout(
  sessionId,
  {
    hostAbsenceGraceMs = HOST_ABSENCE_GRACE_MS,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = {}
) {
  const session = sessions.get(sessionId);
  if (!session || session.host || session.hostAbsenceTimer) {
    return;
  }

  if (session.cleanupTimer) {
    clearTimeoutFn(session.cleanupTimer);
    session.cleanupTimer = null;
  }

  session.hostAbsenceTimer = setTimeoutFn(() => {
    const active = sessions.get(sessionId);
    if (!active) {
      return;
    }
    active.hostAbsenceTimer = null;
    active.notificationSecret = null;
    unregisterLiveHostSession(active.hostRegistration, sessionId);
    if (active.android && (active.android.readyState === WebSocket.OPEN || active.android.readyState === WebSocket.CONNECTING)) {
      active.android.close(CLOSE_CODE_SESSION_UNAVAILABLE, "Host disconnected");
    }
    scheduleCleanup(sessionId, { setTimeoutFn });
  }, hostAbsenceGraceMs);
  session.hostAbsenceTimer.unref?.();
}

function clearHostAbsenceTimer(session, { clearTimeoutFn = clearTimeout } = {}) {
  if (!session?.hostAbsenceTimer) {
    return;
  }
  clearTimeoutFn(session.hostAbsenceTimer);
  session.hostAbsenceTimer = null;
}

function canAcceptAndroidConnection(session) {
  if (!session) {
    return false;
  }
  if (session.host?.readyState === WebSocket.OPEN) {
    return true;
  }
  return Boolean(session.hostAbsenceTimer);
}

function getRelayStats() {
  let sessionsWithHost = 0;
  let sessionsWithAndroid = 0;
  for (const session of sessions.values()) {
    if (session.host) {
      sessionsWithHost += 1;
    }
    if (session.android) {
      sessionsWithAndroid += 1;
    }
  }
  return {
    activeSessions: sessions.size,
    sessionsWithHost,
    sessionsWithAndroid,
  };
}

function hasActiveHostSession(sessionId) {
  if (typeof sessionId !== "string" || !sessionId.trim()) {
    return false;
  }
  const session = sessions.get(sessionId.trim());
  return Boolean(session?.host && session.host.readyState === WebSocket.OPEN);
}

function hasAuthenticatedHostSession(sessionId, notificationSecret) {
  if (!hasActiveHostSession(sessionId)) {
    return false;
  }
  const session = sessions.get(sessionId.trim());
  return session?.notificationSecret === readHeaderString(notificationSecret);
}

function resolveTrustedHostSession({
  hostDeviceId,
  androidDeviceId,
  androidIdentityPublicKey,
  timestamp,
  nonce,
  signature,
  now = Date.now(),
} = {}) {
  const normalizedHostDeviceId = normalizeNonEmptyString(hostDeviceId);
  const normalizedAndroidDeviceId = normalizeNonEmptyString(androidDeviceId);
  const normalizedAndroidIdentityPublicKey = normalizeNonEmptyString(androidIdentityPublicKey);
  const normalizedNonce = normalizeNonEmptyString(nonce);
  const normalizedSignature = normalizeNonEmptyString(signature);
  const normalizedTimestamp = Number(timestamp);

  if (
    !normalizedHostDeviceId
    || !normalizedAndroidDeviceId
    || !normalizedAndroidIdentityPublicKey
    || !normalizedNonce
    || !normalizedSignature
    || !Number.isFinite(normalizedTimestamp)
  ) {
    throw createRelayError(400, "invalid_request", "Trusted session resolve payload is missing required fields.");
  }

  if (Math.abs(now - normalizedTimestamp) > TRUSTED_SESSION_RESOLVE_SKEW_MS) {
    throw createRelayError(401, "resolve_request_expired", "Trusted session resolve request expired.");
  }

  pruneUsedResolveNonces(now);
  const nonceKey = `${normalizedHostDeviceId}|${normalizedAndroidDeviceId}|${normalizedNonce}`;
  if (usedResolveNonces.has(nonceKey)) {
    throw createRelayError(409, "resolve_request_replayed", "Trusted session resolve request already used.");
  }

  const liveSession = liveSessionsByHostDeviceId.get(normalizedHostDeviceId);
  if (!liveSession || !hasActiveHostSession(liveSession.sessionId)) {
    throw createRelayError(404, "session_unavailable", "Trusted host is offline.");
  }

  if (
    liveSession.trustedAndroidDeviceId !== normalizedAndroidDeviceId
    || liveSession.trustedAndroidPublicKey !== normalizedAndroidIdentityPublicKey
  ) {
    throw createRelayError(403, "android_not_trusted", "This Android device is not trusted for this host.");
  }

  const transcript = buildTrustedSessionResolveBytes({
    hostDeviceId: normalizedHostDeviceId,
    androidDeviceId: normalizedAndroidDeviceId,
    androidIdentityPublicKey: normalizedAndroidIdentityPublicKey,
    nonce: normalizedNonce,
    timestamp: normalizedTimestamp,
  });
  const signatureValid = verifyTrustedSessionResolveSignature(
    normalizedAndroidIdentityPublicKey,
    transcript,
    normalizedSignature
  );
  if (!signatureValid) {
    throw createRelayError(403, "invalid_signature", "Trusted session resolve signature is invalid.");
  }

  usedResolveNonces.set(nonceKey, now + TRUSTED_SESSION_RESOLVE_SKEW_MS);
  return {
    ok: true,
    hostDeviceId: normalizedHostDeviceId,
    hostIdentityPublicKey: liveSession.hostIdentityPublicKey,
    displayName: liveSession.displayName || null,
    sessionId: liveSession.sessionId,
  };
}

function buildTrustedSessionResolveBytes({
  hostDeviceId,
  androidDeviceId,
  androidIdentityPublicKey,
  nonce,
  timestamp,
}) {
  return Buffer.concat([
    encodeLengthPrefixedUTF8(TRUSTED_SESSION_RESOLVE_TAG),
    encodeLengthPrefixedUTF8(hostDeviceId),
    encodeLengthPrefixedUTF8(androidDeviceId),
    encodeLengthPrefixedData(Buffer.from(androidIdentityPublicKey, "base64")),
    encodeLengthPrefixedUTF8(nonce),
    encodeLengthPrefixedUTF8(String(timestamp)),
  ]);
}

function verifyTrustedSessionResolveSignature(publicKeyBase64, transcript, signatureBase64) {
  try {
    return verify(null, transcript, resolveEd25519PublicKey(publicKeyBase64), Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

function encodeLengthPrefixedUTF8(value) {
  return encodeLengthPrefixedData(Buffer.from(String(value), "utf8"));
}

function encodeLengthPrefixedData(value) {
  const lengthBuffer = Buffer.allocUnsafe(4);
  lengthBuffer.writeUInt32BE(value.length, 0);
  return Buffer.concat([lengthBuffer, value]);
}

function pruneUsedResolveNonces(now) {
  for (const [key, expiresAt] of usedResolveNonces.entries()) {
    if (now >= expiresAt) {
      usedResolveNonces.delete(key);
    }
  }
}

function registerLiveHostSession(registration) {
  if (!registration?.hostDeviceId) {
    return;
  }
  liveSessionsByHostDeviceId.set(registration.hostDeviceId, registration);
}

function unregisterLiveHostSession(registration, sessionId) {
  const hostDeviceId = registration?.hostDeviceId;
  if (!hostDeviceId) {
    return;
  }
  const current = liveSessionsByHostDeviceId.get(hostDeviceId);
  if (current?.sessionId === sessionId) {
    liveSessionsByHostDeviceId.delete(hostDeviceId);
  }
}

function applyHostRegistrationMessage(session, sessionId, rawMessage) {
  const parsed = safeParseJSON(rawMessage);
  if (parsed?.kind !== "relayHostRegistration" || typeof parsed.registration !== "object") {
    return false;
  }
  session.hostRegistration = normalizeHostRegistration(parsed.registration, sessionId);
  registerLiveHostSession(session.hostRegistration);
  return true;
}

function readHostRegistrationHeaders(headers, sessionId) {
  return normalizeHostRegistration({
    hostDeviceId: readHeaderString(headers["x-host-device-id"]),
    hostIdentityPublicKey: readHeaderString(headers["x-host-identity-public-key"]),
    displayName: readHeaderString(headers["x-host-name"]),
    trustedAndroidDeviceId: readHeaderString(headers["x-trusted-android-device-id"]),
    trustedAndroidPublicKey: readHeaderString(headers["x-trusted-android-public-key"]),
  }, sessionId);
}

function normalizeHostRegistration(registration, sessionId) {
  return {
    sessionId,
    hostDeviceId: normalizeNonEmptyString(registration?.hostDeviceId),
    hostIdentityPublicKey: normalizeNonEmptyString(registration?.hostIdentityPublicKey),
    displayName: normalizeNonEmptyString(registration?.displayName),
    trustedAndroidDeviceId: normalizeNonEmptyString(registration?.trustedAndroidDeviceId),
    trustedAndroidPublicKey: normalizeNonEmptyString(registration?.trustedAndroidPublicKey),
  };
}

function relaySessionLogLabel(sessionId) {
  const normalizedSessionId = normalizeNonEmptyString(sessionId);
  if (!normalizedSessionId) {
    return "session=[redacted]";
  }
  const digest = createHash("sha256")
    .update(normalizedSessionId)
    .digest("hex")
    .slice(0, 8);
  return `session#${digest}`;
}

function readHeaderString(value) {
  const candidate = Array.isArray(value) ? value[0] : value;
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : "";
}

function resolveConnectionRole(req) {
  const fromHeader = readHeaderString(req.headers["x-role"]).toLowerCase();
  if (fromHeader === "host" || fromHeader === "android") {
    return fromHeader;
  }

  try {
    const url = new URL(req.url || "/", "http://relay.local");
    const fromQuery = readHeaderString(url.searchParams.get("role")).toLowerCase();
    if (fromQuery === "host" || fromQuery === "android") {
      return fromQuery;
    }
  } catch {
    // ignore malformed URL
  }

  return "";
}

function normalizeNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function createRelayError(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

function safeParseJSON(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function base64ToBase64Url(value) {
  return String(value || "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function resolveEd25519PublicKey(publicKeyBase64) {
  try {
    return createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
  } catch {
    return createPublicKey({
      key: {
        crv: "Ed25519",
        kty: "OKP",
        x: base64ToBase64Url(publicKeyBase64),
      },
      format: "jwk",
    });
  }
}

function __resetRelayStateForTests() {
  sessions.clear();
  liveSessionsByHostDeviceId.clear();
  usedResolveNonces.clear();
}

module.exports = {
  TRUSTED_SESSION_RESOLVE_TAG,
  buildTrustedSessionResolveBytes,
  getRelayStats,
  hasActiveHostSession,
  hasAuthenticatedHostSession,
  resolveTrustedHostSession,
  setupRelay,
  verifyTrustedSessionResolveSignature,
  __resetRelayStateForTests,
};
