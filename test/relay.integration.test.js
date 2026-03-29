const test = require("node:test");
const assert = require("node:assert/strict");
const { generateKeyPairSync, sign } = require("crypto");
const WebSocket = require("ws");

const { createRelayServer } = require("../server");
const {
  TRUSTED_SESSION_RESOLVE_TAG,
  __resetRelayStateForTests,
} = require("../relay");

test.afterEach(() => {
  __resetRelayStateForTests();
});

test("forwards messages between host and android", async () => {
  const ctx = await startRelay();
  try {
    const sessionId = "session-forward-1";
    const host = await openWS(`${ctx.wsBase}/relay/${sessionId}`, {
      "x-role": "host",
      "x-host-device-id": "host-1",
      "x-host-identity-public-key": Buffer.from("host").toString("base64"),
    });
    const android = await openWS(`${ctx.wsBase}/relay/${sessionId}`, {
      "x-role": "android",
    });

    const fromHost = waitMessage(android);
    host.send(JSON.stringify({ method: "ping" }));
    assert.equal(await fromHost, JSON.stringify({ method: "ping" }));

    const fromAndroid = waitMessage(host);
    android.send(JSON.stringify({ method: "pong" }));
    assert.equal(await fromAndroid, JSON.stringify({ method: "pong" }));

    host.close();
    android.close();
  } finally {
    await ctx.close();
  }
});

test("accepts browser android role via query parameter", async () => {
  const ctx = await startRelay();
  try {
    const sessionId = "session-query-role-1";
    const host = await openWS(`${ctx.wsBase}/relay/${sessionId}`, {
      "x-role": "host",
      "x-host-device-id": "host-query-1",
      "x-host-identity-public-key": Buffer.from("host-query").toString("base64"),
    });

    const android = await openWS(`${ctx.wsBase}/relay/${sessionId}?role=android`);
    const fromAndroid = waitMessage(host);
    android.send(JSON.stringify({ kind: "clientHello", sessionId }));
    assert.equal(await fromAndroid, JSON.stringify({ kind: "clientHello", sessionId }));

    host.close();
    android.close();
  } finally {
    await ctx.close();
  }
});

test("trusted resolve validates signature and blocks nonce replay", async () => {
  const ctx = await startRelay();
  try {
    const sessionId = "session-trust-1";
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const androidPublicKeyBase64 = base64UrlToBase64(publicKey.export({ format: "jwk" }).x);
    const hostIdentityPublicKey = Buffer.from("host-public").toString("base64");

    const host = await openWS(`${ctx.wsBase}/relay/${sessionId}`, {
      "x-role": "host",
      "x-host-device-id": "host-123",
      "x-host-identity-public-key": hostIdentityPublicKey,
      "x-trusted-android-device-id": "android-123",
      "x-trusted-android-public-key": androidPublicKeyBase64,
    });

    const nonce = "nonce-abc";
    const timestamp = Date.now();
    const transcript = trustedResolveTranscript({
      hostDeviceId: "host-123",
      androidDeviceId: "android-123",
      androidIdentityPublicKey: androidPublicKeyBase64,
      nonce,
      timestamp,
    });
    const signature = sign(null, transcript, privateKey).toString("base64");

    const first = await postJSON(`${ctx.httpBase}/v1/trusted/session/resolve`, {
      hostDeviceId: "host-123",
      androidDeviceId: "android-123",
      androidIdentityPublicKey: androidPublicKeyBase64,
      nonce,
      timestamp,
      signature,
    });
    assert.equal(first.status, 200);
    assert.equal(first.body.ok, true);
    assert.equal(first.body.sessionId, sessionId);

    const second = await postJSON(`${ctx.httpBase}/v1/trusted/session/resolve`, {
      hostDeviceId: "host-123",
      androidDeviceId: "android-123",
      androidIdentityPublicKey: androidPublicKeyBase64,
      nonce,
      timestamp,
      signature,
    });
    assert.equal(second.status, 409);
    assert.equal(second.body.code, "resolve_request_replayed");
    host.close();
  } finally {
    await ctx.close();
  }
});

test("serves web app static assets at /app", async () => {
  const ctx = await startRelay();
  try {
    const appResponse = await fetch(`${ctx.httpBase}/app`);
    const appHtml = await appResponse.text();
    assert.equal(appResponse.status, 200);
    assert.match(appHtml, /Androdex Web/);

    const scriptResponse = await fetch(`${ctx.httpBase}/app/app.js`);
    const scriptText = await scriptResponse.text();
    assert.equal(scriptResponse.status, 200);
    assert.match(scriptText, /connectToRelay/);
  } finally {
    await ctx.close();
  }
});

function trustedResolveTranscript({
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

function encodeLengthPrefixedUTF8(value) {
  return encodeLengthPrefixedData(Buffer.from(String(value), "utf8"));
}

function encodeLengthPrefixedData(buffer) {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(buffer.length, 0);
  return Buffer.concat([length, buffer]);
}

function base64UrlToBase64(value) {
  const padded = `${value}${"=".repeat((4 - (value.length % 4 || 4)) % 4)}`;
  return padded.replace(/-/g, "+").replace(/_/g, "/");
}

async function startRelay() {
  const { server } = createRelayServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = address.port;
  return {
    wsBase: `ws://127.0.0.1:${port}`,
    httpBase: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function openWS(url, headers) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers });
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

function waitMessage(socket) {
  return new Promise((resolve) => {
    socket.once("message", (data) => {
      resolve(typeof data === "string" ? data : data.toString("utf8"));
    });
  });
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  return { status: response.status, body: payload };
}
