const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer } = require("ws");
const {
  getRelayStats,
  resolveTrustedHostSession,
  setupRelay,
} = require("./relay");

const WEB_APP_DIR = path.resolve(__dirname, "..", "androdex-web", "public");

function createRelayServer() {
  const server = http.createServer((req, res) => {
    void handleHttp(req, res);
  });
  const wss = new WebSocketServer({ noServer: true });
  setupRelay(wss);

  server.on("upgrade", (req, socket, head) => {
    const pathname = safePathname(req.url);
    if (!pathname.startsWith("/relay/")) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });

  return { server, wss };
}

async function handleHttp(req, res) {
  applyCorsHeaders(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  const pathname = safePathname(req.url);

  if (req.method === "GET" && (pathname === "/app" || pathname.startsWith("/app/"))) {
    return serveWebApp(req, res, pathname);
  }

  if (req.method === "GET" && pathname === "/health") {
    return writeJSON(res, 200, {
      ok: true,
      relay: getRelayStats(),
    });
  }

  if (req.method === "POST" && pathname === "/v1/trusted/session/resolve") {
    return handleJSONRoute(req, res, async (body) => resolveTrustedHostSession(body));
  }

  return writeJSON(res, 404, {
    ok: false,
    error: "Not found",
  });
}

async function handleJSONRoute(req, res, handler) {
  try {
    const body = await readJSONBody(req);
    const result = await handler(body);
    return writeJSON(res, 200, result);
  } catch (error) {
    return writeJSON(res, error.status || 500, {
      ok: false,
      error: error.message || "Internal server error",
      code: error.code || "internal_error",
    });
  }
}

function readJSONBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > 64 * 1024) {
        reject(Object.assign(new Error("Request too large"), {
          status: 413,
          code: "body_too_large",
        }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error("Invalid JSON body"), {
          status: 400,
          code: "invalid_json",
        }));
      }
    });

    req.on("error", reject);
  });
}

function writeJSON(res, status, body) {
  res.statusCode = status;
  applyCorsHeaders(res);
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function serveWebApp(req, res, pathname) {
  let relativePath = pathname === "/app" ? "index.html" : pathname.slice("/app/".length);
  if (!relativePath || relativePath.endsWith("/")) {
    relativePath = `${relativePath}index.html`;
  }
  relativePath = relativePath.replace(/^\/+/, "");
  const resolvedPath = path.resolve(WEB_APP_DIR, relativePath);
  if (!resolvedPath.startsWith(WEB_APP_DIR)) {
    return writeText(res, 403, "Forbidden");
  }

  if (!fs.existsSync(resolvedPath) || fs.statSync(resolvedPath).isDirectory()) {
    const fallbackPath = path.join(WEB_APP_DIR, "index.html");
    if (!fs.existsSync(fallbackPath)) {
      return writeText(res, 404, "Web app not found");
    }
    return sendFile(res, fallbackPath);
  }

  return sendFile(res, resolvedPath);
}

function sendFile(res, filePath) {
  const contentType = mimeTypeFor(filePath);
  try {
    const data = fs.readFileSync(filePath);
    res.statusCode = 200;
    res.setHeader("content-type", contentType);
    res.end(data);
  } catch {
    writeText(res, 500, "Internal server error");
  }
}

function writeText(res, status, text) {
  res.statusCode = status;
  applyCorsHeaders(res);
  res.setHeader("content-type", "text/plain; charset=utf-8");
  res.end(text);
}

function applyCorsHeaders(res) {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type");
}

function mimeTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
    case ".webmanifest":
      return "application/json; charset=utf-8";
    case ".png":
      return "image/png";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

function safePathname(url) {
  try {
    return new URL(url || "/", "http://localhost").pathname;
  } catch {
    return "/";
  }
}

if (require.main === module) {
  const port = Number(process.env.PORT || 9000);
  const host = process.env.HOST || "0.0.0.0";
  const { server } = createRelayServer();
  server.listen(port, host, () => {
    console.log(`[androdex-relay] listening on http://${host}:${port}`);
  });
}

module.exports = {
  createRelayServer,
};
