import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { Readable } from "node:stream";
import zlib from "node:zlib";

const SDK_VERSION = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const PROFILE_RE = /^[a-z][a-z0-9-]{0,47}$/;
const CODE_RE = /^[A-Z0-9_]{1,64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const JSON_BOUND = 16 * 1024 * 1024;
const TRANSFER_BOUND = 1024 * 1024 * 1024;
const CALL_PAYLOAD_LIMIT = 65536;

export class SandcrabError extends Error {
  constructor(status, code, recoveryId = null) {
    const suffix = recoveryId ? ` (recoveryId=${recoveryId})` : "";
    super(`Sandcrab API: HTTP ${status} ${code}${suffix}`);
    this.name = "SandcrabError";
    this.status = status;
    this.code = code;
    this.recoveryId = recoveryId;
  }
}

export class TransportUncertainError extends Error {
  constructor(operation, recoveryId, cause = undefined) {
    super(`${operation} reply was lost; inspect ${recoveryId} instead of submitting a new ID`);
    this.name = "TransportUncertainError";
    this.operation = operation;
    this.recoveryId = recoveryId;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

export class CommandFailedError extends Error {
  constructor(run) {
    const state = run?.state ?? "failed";
    const result = run?.result ?? {};
    const detail =
      result.exitCode !== undefined && result.exitCode !== null
        ? `exitCode=${result.exitCode}`
        : `code=${result.code ?? state}`;
    super(`Sandbox command ${run?.id} ended with state=${state} (${detail})`);
    this.name = "CommandFailedError";
    this.run = run;
  }
}

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProtocolError";
  }
}

export class PublicationUncertainError extends Error {
  constructor(templateId) {
    super(`Publication outcome is unknown; reconcile template ${templateId}`);
    this.name = "PublicationUncertainError";
    this.templateId = templateId;
  }
}

export function checkUuid(value, label = "ID") {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new TypeError(`Invalid canonical ${label}: ${String(value)}`);
  }
  return value;
}

export function checkDigest(value, label = "SHA-256") {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new TypeError(`Invalid ${label}`);
  }
  return value;
}

export function checkProfile(value) {
  if (typeof value !== "string" || !PROFILE_RE.test(value)) {
    throw new TypeError(`Invalid profile name: ${String(value)}`);
  }
  return value;
}

export function checkRelativePath(value, { allowRoot = false } = {}) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    value.includes("\0") ||
    value.includes("\\")
  ) {
    throw new TypeError("Invalid workspace path");
  }
  if (value === ".") {
    if (allowRoot) return value;
    throw new TypeError("Workspace root '.' is not valid for this operation");
  }
  if (value.startsWith("/")) {
    throw new TypeError("Workspace path must be relative");
  }
  const parts = value.split("/");
  if (parts.some((p) => p === "" || p === "." || p === "..")) {
    throw new TypeError("Workspace path must be normalized and relative");
  }
  return value;
}

export function recipeId(layers) {
  if (
    !Array.isArray(layers) ||
    layers.length < 1 ||
    layers.length > 16 ||
    layers.some((layer) => typeof layer !== "string" || !DIGEST_RE.test(layer)) ||
    new Set(layers).size !== layers.length
  ) {
    throw new TypeError("Use 1 to 16 distinct immutable layer IDs in base-to-top order");
  }
  const hash = createHash("sha256");
  hash.update(Buffer.from("sandcrab-template-recipe-v1\0", "ascii"));
  const count = Buffer.alloc(4);
  count.writeUInt32LE(layers.length, 0);
  hash.update(count);
  for (const layer of layers) {
    hash.update(Buffer.from(layer, "ascii"));
  }
  return hash.digest("hex");
}

function isLoopbackHost(rawHost) {
  const host = rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost;
  const kind = net.isIP(host);
  if (kind === 4) {
    return host.startsWith("127.");
  }
  if (kind === 6) {
    const lower = host.toLowerCase();
    if (lower === "::1") return true;
    const expanded = lower.split(":");
    return (
      !lower.includes("::") &&
      expanded.length === 8 &&
      expanded.slice(0, 7).every((part) => /^0{1,4}$/.test(part)) &&
      /^0{0,3}1$/.test(expanded[7])
    );
  }
  return false;
}

function parseLoopbackEndpoint(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new TypeError("Invalid HTTP endpoint URL");
  }
  const port = Number(parsed.port);
  if (
    parsed.protocol !== "http:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (parsed.pathname !== "/" && parsed.pathname !== "") ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    !parsed.port ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    !isLoopbackHost(parsed.hostname)
  ) {
    throw new TypeError("Use an HTTP endpoint with a literal loopback address and explicit port");
  }
  const host = parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]")
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;
  return { host, port };
}

function readTokenFile(filePath) {
  if (process.platform !== "win32") {
    const info = fs.lstatSync(filePath);
    const euid = typeof process.geteuid === "function" ? process.geteuid() : info.uid;
    if (!info.isFile() || (info.uid !== 0 && info.uid !== euid) || (info.mode & 0o077) !== 0) {
      throw new TypeError(
        "Service token file must be a private regular file (mode 0400/0600) owned by root or the caller"
      );
    }
  }
  const raw = fs.readFileSync(filePath);
  if (raw.length > 256) {
    throw new TypeError("Service token file exceeds 256 bytes");
  }
  const token = raw.toString("utf8").replace(/[\r\n]+$/, "");
  if (!DIGEST_RE.test(token)) {
    throw new TypeError("Service token must be 64 lowercase hexadecimal characters");
  }
  return token;
}

function checkUnixSocket(socketPath, requireSocketStat) {
  if (typeof socketPath !== "string" || !path.isAbsolute(socketPath)) {
    throw new TypeError("Unix socket path must be absolute");
  }
  if (!requireSocketStat) {
    return socketPath;
  }
  if (process.platform === "win32") {
    throw new TypeError("Unix domain socket transport requires a POSIX host");
  }
  const info = fs.lstatSync(socketPath);
  if (!info.isSocket() || info.uid !== 0) {
    throw new TypeError(`Unix control socket must be a root-owned socket: ${socketPath}`);
  }
  return socketPath;
}

function resolveConnection(options = {}) {
  const env = options.env ?? process.env;
  let { socketPath, endpoint } = options;
  const { token, tokenFile, requireSocketStat = true } = options;

  if (socketPath !== undefined && endpoint !== undefined) {
    throw new TypeError("Pass either socketPath or endpoint, not both");
  }
  if (socketPath === undefined && endpoint === undefined) {
    const envSocket = env.SANDCRAB_SOCKET || undefined;
    const envEndpoint = env.SANDCRAB_ENDPOINT || undefined;
    if (envSocket && envEndpoint) {
      throw new TypeError(
        "Both SANDCRAB_SOCKET and SANDCRAB_ENDPOINT are set; pass socketPath or endpoint explicitly"
      );
    }
    socketPath = envSocket;
    endpoint = envEndpoint;
  }
  if (socketPath !== undefined) {
    return {
      socketPath: checkUnixSocket(socketPath, requireSocketStat),
      host: "localhost",
      port: undefined,
      headers: {},
    };
  }
  if (endpoint !== undefined) {
    const { host, port } = parseLoopbackEndpoint(endpoint);
    if (token !== undefined && tokenFile !== undefined) {
      throw new TypeError("Pass either token or tokenFile, not both");
    }
    let resolvedToken = token;
    if (resolvedToken === undefined) {
      const chosenFile = tokenFile ?? env.SANDCRAB_TOKEN_FILE;
      if (!chosenFile) {
        throw new TypeError("Loopback HTTP transport requires token, tokenFile or SANDCRAB_TOKEN_FILE");
      }
      resolvedToken = readTokenFile(chosenFile);
    } else if (!DIGEST_RE.test(resolvedToken)) {
      throw new TypeError("Service token must be 64 lowercase hexadecimal characters");
    }
    return {
      socketPath: undefined,
      host,
      port,
      headers: { Authorization: `Bearer ${resolvedToken}` },
    };
  }
  throw new TypeError("Configure socketPath, endpoint, SANDCRAB_SOCKET or SANDCRAB_ENDPOINT");
}

function formatByteRange(spec) {
  if (typeof spec === "string") {
    const text = spec.startsWith("bytes=") ? spec.slice(6) : spec;
    const dash = text.indexOf("-");
    if (text.includes(",") || dash === -1) {
      throw new TypeError("Byte range must be START-END, START- or -SUFFIX");
    }
    const start = text.slice(0, dash);
    const end = text.slice(dash + 1);
    if ((!start && !end) || (start && !/^\d+$/.test(start)) || (end && !/^\d+$/.test(end))) {
      throw new TypeError("Invalid byte range bounds");
    }
    return `bytes=${start}-${end}`;
  }
  if (!spec || typeof spec !== "object") {
    throw new TypeError("Invalid byte range specification");
  }
  const { start, end, suffix } = spec;
  if (suffix !== undefined) {
    if (!Number.isInteger(suffix) || suffix <= 0 || start !== undefined || end !== undefined) {
      throw new TypeError("Suffix byte range must be a positive integer without start/end");
    }
    return `bytes=-${suffix}`;
  }
  if (!Number.isInteger(start) || start < 0) {
    throw new TypeError("Range start must be a non-negative integer");
  }
  if (end !== undefined && (!Number.isInteger(end) || end < start)) {
    throw new TypeError("Range end must be an integer >= start");
  }
  return `bytes=${start}-${end === undefined ? "" : end}`;
}

function parseJsonResponse(status, buf, recoveryId = null) {
  let parsed;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch (err) {
    throw new ProtocolError(`Daemon returned non-JSON body (HTTP ${status}): ${err.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ProtocolError("Daemon JSON response must be an object");
  }
  if (status >= 400) {
    const rawCode = parsed.error?.code ?? parsed.code;
    const code = typeof rawCode === "string" && CODE_RE.test(rawCode) ? rawCode : "API_ERROR";
    throw new SandcrabError(status, code, recoveryId);
  }
  return parsed;
}

async function* parseSseStream(response) {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let eventId = null;
  let eventType = "message";
  let dataLines = [];

  const processLine = (rawLine) => {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line === "") {
      if (dataLines.length > 0) {
        const payload = dataLines.join("\n");
        dataLines = [];
        const frame = { id: eventId, event: eventType, data: JSON.parse(payload) };
        eventType = "message";
        return frame;
      }
      return null;
    }
    if (line.startsWith(":")) {
      return null;
    }
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let rest = colon === -1 ? "" : line.slice(colon + 1);
    if (rest.startsWith(" ")) rest = rest.slice(1);
    if (field === "id") eventId = rest;
    else if (field === "event") eventType = rest;
    else if (field === "data") dataLines.push(rest);
    return null;
  };

  for await (const chunk of response) {
    buffer += decoder.decode(chunk, { stream: true });
    let newline;
    while ((newline = buffer.indexOf("\n")) !== -1) {
      const rawLine = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      const frame = processLine(rawLine);
      if (frame) yield frame;
    }
  }
  buffer += decoder.decode();
  if (buffer.length > 0) {
    const frame = processLine(buffer);
    if (frame) yield frame;
  }
  if (dataLines.length > 0) {
    throw new ProtocolError("Incomplete SSE frame before stream EOF");
  }
}

function isGzipBufferOrFile(source) {
  if (Buffer.isBuffer(source) || source instanceof Uint8Array) {
    return source.length >= 2 && source[0] === 0x1f && source[1] === 0x8b;
  }
  const filePath = String(source);
  const lower = path.basename(filePath).toLowerCase();
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return true;
  }
  const fd = fs.openSync(filePath, "r");
  try {
    const head = Buffer.alloc(2);
    const read = fs.readSync(fd, head, 0, 2, 0);
    return read === 2 && head[0] === 0x1f && head[1] === 0x8b;
  } finally {
    fs.closeSync(fd);
  }
}

async function* iterTarChunks(source, limit = TRANSFER_BOUND) {
  const gzipped = isGzipBufferOrFile(source);
  let total = 0;
  const checkLimit = (buf) => {
    total += buf.length;
    if (total > limit) {
      throw new RangeError(`Uncompressed template tar exceeds ${limit} bytes`);
    }
    return buf;
  };

  if ((Buffer.isBuffer(source) || source instanceof Uint8Array) && !gzipped) {
    yield checkLimit(Buffer.from(source));
    return;
  }
  const baseStream =
    Buffer.isBuffer(source) || source instanceof Uint8Array
      ? Readable.from([Buffer.from(source)])
      : fs.createReadStream(String(source));
  const stream = gzipped ? baseStream.pipe(zlib.createGunzip()) : baseStream;
  for await (const chunk of stream) {
    yield checkLimit(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
}

export class InMemoryReplyLedger {
  constructor() {
    this._entries = new Map();
  }

  get(runId, callId) {
    return this._entries.get(`${runId}:${callId}`) ?? null;
  }

  put(runId, callId, requestSha256, reply) {
    const key = `${runId}:${callId}`;
    const buf = Buffer.from(reply);
    const existing = this._entries.get(key);
    if (existing && (existing.requestSha256 !== requestSha256 || !existing.reply.equals(buf))) {
      throw new ProtocolError(`Conflicting reply recorded for call ${callId}`);
    }
    this._entries.set(key, { requestSha256, reply: buf });
  }

  get size() {
    return this._entries.size;
  }
}

function encodeReply(result) {
  let buf;
  if (Buffer.isBuffer(result)) {
    buf = result;
  } else if (result instanceof Uint8Array) {
    buf = Buffer.from(result);
  } else if (typeof result === "string") {
    buf = Buffer.from(result, "utf8");
  } else {
    buf = Buffer.from(JSON.stringify(result), "utf8");
  }
  if (buf.length > CALL_PAYLOAD_LIMIT) {
    throw new RangeError(`Host-call reply exceeds ${CALL_PAYLOAD_LIMIT} bytes`);
  }
  return buf;
}

const pendingCallsByLedger = new WeakMap();

export class HostCallDispatcher {
  constructor({ ledger = new InMemoryReplyLedger(), operationField = "operation" } = {}) {
    this.ledger = ledger;
    if (!pendingCallsByLedger.has(ledger)) pendingCallsByLedger.set(ledger, new Map());
    this._pending = pendingCallsByLedger.get(ledger);
    this.operationField = operationField;
    this._rawHandler = null;
    this._jsonHandlers = new Map();
  }

  onCall(handler) {
    this._rawHandler = handler;
    return this;
  }

  onJson(operation, handler) {
    this._jsonHandlers.set(operation, handler);
    return this;
  }

  async handlePayload(payload, context) {
    const { runId, callId, requestSha256 } = context;
    const key = `${runId}:${callId}`;
    const pending = this._pending.get(key);
    if (pending) {
      if (pending.requestSha256 !== requestSha256) {
        throw new ProtocolError(`Call ${callId} changed its request bytes`);
      }
      return pending.reply;
    }
    const reply = Promise.resolve().then(() => this._dispatch(payload, context));
    this._pending.set(key, { requestSha256, reply });
    try {
      return await reply;
    } finally {
      this._pending.delete(key);
    }
  }

  async _dispatch(payload, context) {
    const cached = await this.ledger.get(context.runId, context.callId);
    if (cached) {
      if (cached.requestSha256 !== context.requestSha256) {
        throw new ProtocolError(`Call ${context.callId} changed its request bytes`);
      }
      return cached.reply;
    }
    if (this._jsonHandlers.size > 0) {
      const parsed = JSON.parse(payload.toString("utf8"));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Host-call JSON payload must be an object");
      }
      const op = parsed[this.operationField];
      if (typeof op === "string" && this._jsonHandlers.has(op)) {
        const reply = encodeReply(await this._jsonHandlers.get(op)(parsed, context));
        await this.ledger.put(context.runId, context.callId, context.requestSha256, reply);
        return reply;
      }
      if (!this._rawHandler) {
        throw new Error(`Unauthorized or unknown host-call operation: ${String(op)}`);
      }
    }
    if (!this._rawHandler) {
      throw new Error("No host-call handler registered");
    }
    const reply = encodeReply(await this._rawHandler(payload, context));
    await this.ledger.put(context.runId, context.callId, context.requestSha256, reply);
    return reply;
  }

  async drive(client, runId, { expectedServerId = null, after = null } = {}) {
    let cursor = after;
    let verifiedEpoch = expectedServerId;
    try {
      for (let attempt = 0; attempt < 64; attempt += 1) {
        let reconnect = false;
        for await (const frame of client.streamCallEvents(runId, { after: cursor })) {
          if (frame.id) cursor = frame.id;
          if (frame.event === "state") {
            const state = frame.data ?? {};
            if (state.runId !== runId) {
              throw new ProtocolError("Host-call stream runId mismatch");
            }
            if (typeof state.serverId !== "string" || (verifiedEpoch && state.serverId !== verifiedEpoch)) {
              throw new ProtocolError("Host-call stream serverId mismatch");
            }
            verifiedEpoch = state.serverId;
          } else if (frame.event === "call") {
            if (!verifiedEpoch) {
              throw new ProtocolError("Host-call event preceded initial state frame");
            }
            const data = frame.data ?? {};
            if (typeof data.base64 !== "string") {
              throw new ProtocolError("Host-call event is missing base64 payload");
            }
            const payload = Buffer.from(data.base64, "base64");
            if (payload.length > CALL_PAYLOAD_LIMIT || payload.toString("base64") !== data.base64) {
              throw new ProtocolError("Invalid host-call base64 payload");
            }
            const digest = createHash("sha256").update(payload).digest("hex");
            if (data.requestSha256 !== undefined && data.requestSha256 !== digest) {
              throw new ProtocolError("Host-call payload digest mismatch");
            }
            if (typeof data.id !== "string" || !data.id || data.id === data.requestId) {
              throw new ProtocolError("Invalid daemon host-call handle");
            }
            const ctx = {
              runId,
              serverId: verifiedEpoch,
              callId: data.id,
              guestRequestId: String(data.requestId ?? ""),
              sequence: Number(data.sequence ?? 0),
              requestSha256: digest,
              cursor: frame.id ?? null,
            };
            const reply = await this.handlePayload(payload, ctx);
            await client.replyCall(runId, ctx.callId, reply);
          } else if (frame.event === "result") {
            return frame.data?.run ?? frame.data;
          } else if (frame.event === "error") {
            const code = frame.data?.code ?? "CALL_STREAM_ERROR";
            if (code === "OBSERVATION_TIMEOUT" && cursor) {
              reconnect = true;
              break;
            }
            throw new ProtocolError(`Host-call stream ended with error: ${code}`);
          }
        }
        if (!reconnect) break;
      }
    } catch (err) {
      try {
        await client.cancelRun(runId);
      } catch {
        // Best-effort cancellation on handler or stream failure.
      }
      throw err;
    }
    throw new ProtocolError("Host-call stream closed before terminal result frame");
  }
}

export class SandcrabSession {
  constructor(client, data, { autoClose = true, keepResult = false } = {}) {
    this.client = client;
    this.data = data;
    this.id = data.id;
    this.serverId = data.serverId;
    this.profile = data.profile;
    this._autoClose = autoClose;
    this._keepResult = keepResult;
    this._closed = false;
  }

  async refresh() {
    this.data = await this.client.getSession(this.id);
    return this.data;
  }

  async renew(ttlMs) {
    this.data = await this.client.renewSession(this.id, ttlMs);
    return this.data;
  }

  async exec(command, options = {}) {
    return this.client.sessionExec(this.id, command, options);
  }

  async openShell(options = {}) {
    return this.client.openShell(this.id, options);
  }

  async writeFile(filePath, data, options = {}) {
    return this.client.writeFile(this.id, filePath, data, options);
  }

  async readFile(filePath, options = {}) {
    return this.client.readFile(this.id, filePath, options);
  }

  async readText(filePath, options = {}) {
    const buf = await this.readFile(filePath, options);
    return buf.toString(options.encoding ?? "utf8");
  }

  async mkdir(dirPath, options = {}) {
    return this.client.mkdir(this.id, dirPath, options);
  }

  async listFiles(dirPath = ".", options = {}) {
    return this.client.listFiles(this.id, dirPath, options);
  }

  async searchFiles(pattern, options = {}) {
    return this.client.searchFiles(this.id, pattern, options);
  }

  async removeFile(filePath, options = {}) {
    return this.client.removeFile(this.id, filePath, options);
  }

  async diff() {
    return this.client.sessionDiff(this.id);
  }

  async snapshot(options = {}) {
    return this.client.sessionSnapshot(this.id, options);
  }

  async close({ forget = false } = {}) {
    if (!this._closed) {
      this.data = await this.client.closeSession(this.id, { forget });
      this._closed = true;
    } else if (forget) {
      await this.client.forgetSession(this.id);
    }
    return this.data;
  }

  async forget() {
    return this.client.forgetSession(this.id);
  }

  async [Symbol.asyncDispose]() {
    if (!this._autoClose) return;
    await this.close({ forget: !this._keepResult });
  }
}

export class SandcrabClient {
  async workspaceTools(key, options) {
    const { bindWorkspaceTools } = await import("./workspace.js");
    return bindWorkspaceTools(this, key, options);
  }

  constructor(options = {}) {
    const env = options.env ?? process.env;
    this._conn = resolveConnection({ ...options, env });
    const prof = options.defaultProfile ?? env.SANDCRAB_PROFILE;
    this.defaultProfile = prof ? checkProfile(prof) : null;
    this.timeoutMs = options.timeoutMs ?? 75000;
    this._agent = new http.Agent({ keepAlive: false });
    this._serverId = null;
    this._discovery = null;
    this._warnedRelease = null;
  }

  close() {
    this._agent.destroy();
  }

  _resolveProfile(profile) {
    const chosen = profile ?? this.defaultProfile;
    if (!chosen) {
      throw new TypeError("Pass profile or configure defaultProfile / SANDCRAB_PROFILE");
    }
    return checkProfile(chosen);
  }

  async _ensureServerId() {
    if (!this._serverId) {
      this._discovery ??= this.info().finally(() => { this._discovery = null; });
      await this._discovery;
      if (!this._serverId) throw new ProtocolError("Discovery returned no serverId");
    }
    return this._serverId;
  }

  async _openRawRequest(method, route, { headers = {}, body = null, stream = false } = {}) {
    if (!this._serverId && route !== "/v1/info") await this._ensureServerId();
    return new Promise((resolve, reject) => {
      const reqHeaders = { ...this._conn.headers, ...headers };
      let payloadBuffer = null;
      if (body === null || body === undefined) {
        if (method === "POST" && !stream) {
          payloadBuffer = Buffer.from("{}", "utf8");
          reqHeaders["Content-Type"] = "application/json";
          reqHeaders["Content-Length"] = String(payloadBuffer.length);
        }
      } else if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
        payloadBuffer = Buffer.from(body);
        reqHeaders["Content-Length"] = String(payloadBuffer.length);
      } else if (typeof body === "string") {
        payloadBuffer = Buffer.from(body, "utf8");
        reqHeaders["Content-Length"] = String(payloadBuffer.length);
      } else if (!stream) {
        payloadBuffer = Buffer.from(JSON.stringify(body), "utf8");
        reqHeaders["Content-Type"] = "application/json";
        reqHeaders["Content-Length"] = String(payloadBuffer.length);
      }

      const reqOptions = {
        method,
        path: route,
        headers: reqHeaders,
        agent: this._agent,
        timeout: this.timeoutMs,
      };
      if (this._conn.socketPath) {
        reqOptions.socketPath = this._conn.socketPath;
      } else {
        reqOptions.hostname = this._conn.host;
        reqOptions.port = this._conn.port;
      }

      const req = http.request(reqOptions, (res) => resolve(res));
      req.on("timeout", () => {
        req.destroy(new Error(`Sandcrab request timed out after ${this.timeoutMs}ms`));
      });
      req.on("error", reject);

      if (stream && body && typeof body[Symbol.asyncIterator] === "function") {
        (async () => {
          try {
            for await (const chunk of body) {
              if (!req.write(chunk)) {
                await new Promise((r) => req.once("drain", r));
              }
            }
            req.end();
          } catch (err) {
            req.destroy(err);
            reject(err);
          }
        })();
      } else {
        if (payloadBuffer !== null) req.write(payloadBuffer);
        req.end();
      }
    });
  }

  async _requestJson(
    method,
    route,
    { jsonBody = undefined, rawBody = undefined, streamBody = undefined, headers = {}, recoveryId = null, uncertainOp = null } = {}
  ) {
    if (uncertainOp && !this._serverId) await this._ensureServerId();
    let res;
    try {
      const body = streamBody !== undefined ? streamBody : rawBody !== undefined ? rawBody : jsonBody;
      res = await this._openRawRequest(method, route, {
        headers,
        body,
        stream: streamBody !== undefined,
      });
      const chunks = [];
      let total = 0;
      for await (const chunk of res) {
        total += chunk.length;
        if (total > JSON_BOUND) {
          res.destroy();
          throw new ProtocolError("JSON response exceeded client bound");
        }
        chunks.push(chunk);
      }
      return parseJsonResponse(res.statusCode ?? 500, Buffer.concat(chunks), recoveryId);
    } catch (err) {
      if (
        uncertainOp &&
        recoveryId &&
        !(err instanceof SandcrabError) &&
        !(err instanceof ProtocolError) &&
        !(err instanceof TypeError) &&
        !(err instanceof RangeError)
      ) {
        throw new TransportUncertainError(uncertainOp, recoveryId, err);
      }
      throw err;
    }
  }

  async _requestBytes(
    method,
    route,
    { jsonBody = undefined, headers = {}, expectPartial = false, expectEtag = false } = {}
  ) {
    const res = await this._openRawRequest(method, route, { headers, body: jsonBody });
    const status = res.statusCode ?? 500;
    const limit = status >= 400 ? JSON_BOUND : TRANSFER_BOUND;
    const chunks = [];
    let total = 0;
    for await (const chunk of res) {
      total += chunk.length;
      if (total > limit) {
        res.destroy();
        throw new ProtocolError("Binary response exceeded client bound");
      }
      chunks.push(chunk);
    }
    const buf = Buffer.concat(chunks);
    if (status >= 400) {
      parseJsonResponse(status, buf);
    }
    if (this._serverId) {
      const servedEpoch = res.headers["x-sandcrab-server-id"];
      if (servedEpoch && servedEpoch !== this._serverId) {
        throw new ProtocolError("Daemon serverId changed during file read");
      }
    }
    const expectedStatus = expectPartial ? 206 : 200;
    if (status !== expectedStatus) {
      throw new ProtocolError(`Unexpected HTTP status ${status} (expected ${expectedStatus})`);
    }
    if (expectEtag) {
      const etag = res.headers.etag ?? "";
      const expected = `"${createHash("sha256").update(buf).digest("hex")}"`;
      if (etag !== expected) {
        throw new ProtocolError("Downloaded file checksum did not match ETag");
      }
    }
    return buf;
  }

  async info() {
    const data = await this._requestJson("GET", "/v1/info");
    if (typeof data.serverId === "string") {
      this._serverId = checkUuid(data.serverId, "serverId");
    }
    if (typeof data.releaseVersion === "string" && data.releaseVersion !== SDK_VERSION && data.releaseVersion !== this._warnedRelease) {
      this._warnedRelease = data.releaseVersion;
      process.emitWarning("Sandcrab SDK " + SDK_VERSION + " connected to service " + data.releaseVersion, { code: "SANDCRAB_VERSION_MISMATCH" });
    }
    return data;
  }

  async openapi(capability) {
    const route = capability
      ? `/v1/openapi?${new URLSearchParams({ capability }).toString()}`
      : "/v1/openapi";
    return this._requestJson("GET", route);
  }

  async submitRun(command, options = {}) {
    if (!Array.isArray(command) || command.length === 0) {
      throw new TypeError("command must be a non-empty array of argument strings");
    }
    const runId = options.id ? checkUuid(options.id, "runId") : randomUUID();
    const body = {
      id: runId,
      serverId: await this._ensureServerId(),
      profile: this._resolveProfile(options.profile),
      command: command.map(String),
    };
    if (options.timeoutMs !== undefined) body.timeoutMillis = Math.trunc(options.timeoutMs);
    if (options.outputLimitBytes !== undefined) body.outputLimitBytes = Math.trunc(options.outputLimitBytes);
    if (options.memoryBytes !== undefined || options.cpuQuotaPercent !== undefined) {
      body.resources = {};
      if (options.memoryBytes !== undefined) body.resources.memoryBytes = Math.trunc(options.memoryBytes);
      if (options.cpuQuotaPercent !== undefined) body.resources.cpuQuotaPercent = Math.trunc(options.cpuQuotaPercent);
    }
    if (options.keepResult) body.keepResult = true;
    return this._requestJson("POST", "/v1/runs", {
      jsonBody: body,
      recoveryId: runId,
      uncertainOp: "submitRun",
    });
  }

  async getRun(runId) {
    checkUuid(runId, "runId");
    return this._requestJson("GET", `/v1/runs/${runId}`, { recoveryId: runId });
  }

  async listRuns({ after } = {}) {
    const route = after
      ? `/v1/runs?${new URLSearchParams({ after: checkUuid(after, "after") }).toString()}`
      : "/v1/runs";
    return this._requestJson("GET", route);
  }

  async cancelRun(runId) {
    checkUuid(runId, "runId");
    return this._requestJson("POST", `/v1/runs/${runId}/cancel`, { recoveryId: runId });
  }

  async forgetRun(runId) {
    checkUuid(runId, "runId");
    return this._requestJson("POST", `/v1/runs/${runId}/forget`, { recoveryId: runId });
  }

  async waitRun(runId, { pollIntervalMs = 25, timeoutMs = undefined } = {}) {
    checkUuid(runId, "runId");
    const deadline = timeoutMs === undefined ? null : Date.now() + timeoutMs;
    for (;;) {
      const run = await this.getRun(runId);
      if (run.state === "closing") {
        throw new SandcrabError(503, "CONTAINMENT_UNCONFIRMED", runId);
      }
      if (run.state !== "queued" && run.state !== "running") {
        return run;
      }
      if (deadline !== null && Date.now() >= deadline) {
        throw new Error(`Timed out waiting for run ${runId}`);
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }

  async *streamEvents(runId, { after = null } = {}) {
    checkUuid(runId, "runId");
    const headers = after ? { "Last-Event-ID": after } : {};
    const res = await this._openRawRequest("GET", `/v1/runs/${runId}/events`, { headers });
    if ((res.statusCode ?? 500) >= 400) {
      const chunks = [];
      for await (const c of res) chunks.push(c);
      parseJsonResponse(res.statusCode ?? 500, Buffer.concat(chunks), runId);
    }
    yield* parseSseStream(res);
  }

  async *streamCallEvents(runId, { after = null } = {}) {
    checkUuid(runId, "runId");
    const headers = after ? { "Last-Event-ID": after } : {};
    const res = await this._openRawRequest("GET", `/v1/runs/${runId}/calls/events`, { headers });
    if ((res.statusCode ?? 500) >= 400) {
      const chunks = [];
      for await (const c of res) chunks.push(c);
      parseJsonResponse(res.statusCode ?? 500, Buffer.concat(chunks), runId);
    }
    yield* parseSseStream(res);
  }

  async listCalls(runId) {
    checkUuid(runId, "runId");
    return this._requestJson("GET", `/v1/runs/${runId}/calls`, { recoveryId: runId });
  }

  async replyCall(runId, callId, reply) {
    checkUuid(runId, "runId");
    checkUuid(callId, "callId");
    const buf = typeof reply === "string" ? Buffer.from(reply, "utf8") : Buffer.from(reply);
    if (buf.length > CALL_PAYLOAD_LIMIT) {
      throw new RangeError(`Host-call reply exceeds ${CALL_PAYLOAD_LIMIT} bytes`);
    }
    return this._requestJson("POST", `/v1/runs/${runId}/calls/${callId}/reply`, {
      jsonBody: { base64: buf.toString("base64") },
      recoveryId: runId,
    });
  }

  async _observeOutput(runId, onOutput) {
    let cursor = null;
    for (let attempt = 0; attempt < 64; attempt += 1) {
      let reconnect = false;
      for await (const frame of this.streamEvents(runId, { after: cursor })) {
        if (frame.id) cursor = frame.id;
        if (frame.event === "stdout" || frame.event === "stderr") {
          const chunk = Buffer.from(frame.data.base64, "base64");
          await onOutput(frame.event, chunk);
        } else if (frame.event === "result") {
          return;
        } else if (frame.event === "error") {
          const code = frame.data?.code ?? "EVENT_STREAM_ERROR";
          if (code === "OBSERVATION_TIMEOUT" && cursor) {
            reconnect = true;
            break;
          }
          throw new ProtocolError(`Output stream ended with error: ${code}`);
        }
      }
      if (!reconnect) break;
    }
    throw new ProtocolError("Output stream closed before terminal result frame");
  }

  async _completeSubmittedRun(runId, { onOutput, dispatcher, keepResult = false, check = false } = {}) {
    const tasks = [];
    if (dispatcher) {
      tasks.push(dispatcher.drive(this, runId, { expectedServerId: this._serverId }));
    }
    if (onOutput) {
      tasks.push(this._observeOutput(runId, onOutput));
    }
    if (tasks.length > 0) {
      await Promise.all(tasks);
    }
    const result = await this.waitRun(runId);
    if (!keepResult) {
      try {
        await this.forgetRun(runId);
      } catch (err) {
        if (!(err instanceof SandcrabError)) throw err;
      }
    }
    if (check && result.state !== "succeeded") {
      throw new CommandFailedError(result);
    }
    return result;
  }

  async run(command, options = {}) {
    const retainWhileRunning = Boolean(options.keepResult || options.dispatcher || options.onOutput);
    const submitted = await this.submitRun(command, { ...options, keepResult: retainWhileRunning });
    return this._completeSubmittedRun(submitted.id, options);
  }

  async openSession(options = {}) {
    const sessionId = options.id ? checkUuid(options.id, "sessionId") : randomUUID();
    const body = {
      id: sessionId,
      serverId: await this._ensureServerId(),
      profile: this._resolveProfile(options.profile),
    };
    if (options.ttlMs !== undefined) body.ttlMillis = Math.trunc(options.ttlMs);
    if (options.volumeId !== undefined) body.volumeId = checkUuid(options.volumeId, "volumeId");
    if (options.templateId !== undefined) body.templateId = checkDigest(options.templateId, "templateId");
    if (options.rootfs) body.rootfs = true;
    if (options.memoryBytes !== undefined || options.cpuQuotaPercent !== undefined) {
      body.resources = {};
      if (options.memoryBytes !== undefined) body.resources.memoryBytes = Math.trunc(options.memoryBytes);
      if (options.cpuQuotaPercent !== undefined) body.resources.cpuQuotaPercent = Math.trunc(options.cpuQuotaPercent);
    }
    if (options.keepResult) body.keepResult = true;
    await this._requestJson("POST", "/v1/sessions", {
      jsonBody: body,
      recoveryId: sessionId,
      uncertainOp: "openSession",
    });
    const ready = await this.waitSession(sessionId, { terminal: false });
    if (ready.state !== "ready") {
      throw new SandcrabError(409, String(ready.code ?? "SESSION_FAILED"), sessionId);
    }
    return new SandcrabSession(this, ready, {
      autoClose: options.autoClose ?? true,
      keepResult: Boolean(options.keepResult),
    });
  }

  async withSession(optionsOrFn, maybeFn) {
    const options = typeof optionsOrFn === "function" ? {} : optionsOrFn;
    const fn = typeof optionsOrFn === "function" ? optionsOrFn : maybeFn;
    const session = await this.openSession(options);
    try {
      return await fn(session);
    } finally {
      if (session._autoClose) {
        await session.close({ forget: !session._keepResult });
      }
    }
  }

  async openShell(parentSessionId, options = {}) {
    checkUuid(parentSessionId, "parentSessionId");
    const shellId = options.id ? checkUuid(options.id, "sessionId") : randomUUID();
    const body = { id: shellId, serverId: await this._ensureServerId() };
    if (options.keepResult) body.keepResult = true;
    await this._requestJson("POST", `/v1/sessions/${parentSessionId}/shells`, {
      jsonBody: body,
      recoveryId: shellId,
      uncertainOp: "openShell",
    });
    const ready = await this.waitSession(shellId, { terminal: false });
    if (ready.state !== "ready") {
      throw new SandcrabError(409, String(ready.code ?? "SESSION_FAILED"), shellId);
    }
    return new SandcrabSession(this, ready, {
      autoClose: options.autoClose ?? true,
      keepResult: Boolean(options.keepResult),
    });
  }

  async getSession(sessionId) {
    checkUuid(sessionId, "sessionId");
    return this._requestJson("GET", `/v1/sessions/${sessionId}`, { recoveryId: sessionId });
  }

  async listSessions({ after } = {}) {
    const route = after
      ? `/v1/sessions?${new URLSearchParams({ after: checkUuid(after, "after") }).toString()}`
      : "/v1/sessions";
    return this._requestJson("GET", route);
  }

  async renewSession(sessionId, ttlMs) {
    checkUuid(sessionId, "sessionId");
    return this._requestJson("POST", `/v1/sessions/${sessionId}/renew`, {
      jsonBody: { ttlMillis: Math.trunc(ttlMs) },
      recoveryId: sessionId,
    });
  }

  async waitSession(sessionId, { terminal = false, pollIntervalMs = 25, timeoutMs = 35000 } = {}) {
    checkUuid(sessionId, "sessionId");
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const session = await this.getSession(sessionId);
      if (session.state === "closing") {
        throw new SandcrabError(503, "CONTAINMENT_UNCONFIRMED", sessionId);
      }
      if (terminal) {
        if (session.state === "closed" || session.state === "expired" || session.state === "failed") {
          return session;
        }
      } else if (session.state !== "starting") {
        return session;
      }
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for session ${sessionId}`);
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }

  async closeSession(sessionId, { forget = false } = {}) {
    checkUuid(sessionId, "sessionId");
    await this._requestJson("POST", `/v1/sessions/${sessionId}/close`, { recoveryId: sessionId });
    const ended = await this.waitSession(sessionId, { terminal: true });
    if (forget) {
      await this.forgetSession(sessionId);
    }
    return ended;
  }

  async forgetSession(sessionId) {
    checkUuid(sessionId, "sessionId");
    return this._requestJson("POST", `/v1/sessions/${sessionId}/forget`, { recoveryId: sessionId });
  }

  async submitSessionCommand(sessionId, command, options = {}) {
    checkUuid(sessionId, "sessionId");
    if (typeof command !== "string" || command.length === 0) {
      throw new TypeError("session command must be a non-empty shell string");
    }
    const runId = options.id ? checkUuid(options.id, "runId") : randomUUID();
    const body = {
      id: runId,
      serverId: await this._ensureServerId(),
      command,
    };
    if (options.timeoutMs !== undefined) body.timeoutMillis = Math.trunc(options.timeoutMs);
    if (options.outputLimitBytes !== undefined) body.outputLimitBytes = Math.trunc(options.outputLimitBytes);
    if (options.keepResult) body.keepResult = true;
    return this._requestJson("POST", `/v1/sessions/${sessionId}/commands`, {
      jsonBody: body,
      recoveryId: runId,
      uncertainOp: "submitSessionCommand",
    });
  }

  async sessionExec(sessionId, command, options = {}) {
    const retainWhileRunning = Boolean(options.keepResult || options.dispatcher || options.onOutput);
    const submitted = await this.submitSessionCommand(sessionId, command, {
      ...options,
      keepResult: retainWhileRunning,
    });
    return this._completeSubmittedRun(submitted.id, options);
  }

  async writeFile(sessionId, filePath, data, { parents = false, replace = true, mode } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(filePath, { allowRoot: false });
    const payload = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    const params = new URLSearchParams({ path: rel });
    if (!replace) params.set("replace", "false");
    if (parents) params.set("parents", "true");
    if (mode !== undefined) {
      if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
        throw new RangeError("File mode must be between 0 and 0o777");
      }
      params.set("mode", String(mode));
    }
    return this._requestJson("PUT", `/v1/sessions/${sessionId}/files?${params.toString()}`, {
      rawBody: payload,
      headers: { "Content-Type": "application/octet-stream" },
      recoveryId: sessionId,
    });
  }

  async readFile(sessionId, filePath, { byteRange, offset, limit } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(filePath, { allowRoot: false });
    if (byteRange !== undefined && (offset !== undefined || limit !== undefined)) {
      throw new TypeError("Cannot combine byteRange with line offset or limit");
    }
    const params = new URLSearchParams({ path: rel });
    const headers = {};
    const lineMode = offset !== undefined || limit !== undefined;
    if (offset !== undefined) {
      if (!Number.isInteger(offset) || offset < 1) throw new RangeError("Line offset must be >= 1");
      params.set("offset", String(offset));
    }
    if (limit !== undefined) {
      if (!Number.isInteger(limit) || limit < 1) throw new RangeError("Line limit must be >= 1");
      params.set("limit", String(limit));
    }
    if (byteRange !== undefined) {
      headers.Range = formatByteRange(byteRange);
    }
    return this._requestBytes("GET", `/v1/sessions/${sessionId}/files?${params.toString()}`, {
      headers,
      expectPartial: byteRange !== undefined,
      expectEtag: byteRange === undefined && !lineMode,
    });
  }

  async mkdir(sessionId, dirPath, { mode } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(dirPath, { allowRoot: false });
    const body = { path: rel };
    if (mode !== undefined) {
      if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
        throw new RangeError("Directory mode must be between 0 and 0o777");
      }
      body.mode = mode;
    }
    return this._requestJson("POST", `/v1/sessions/${sessionId}/files/mkdir`, { jsonBody: body });
  }

  async listFiles(sessionId, dirPath = ".", { depth = 1 } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(dirPath, { allowRoot: true });
    if (!Number.isInteger(depth) || depth < 0 || depth > 64) {
      throw new RangeError("depth must be between 0 and 64");
    }
    const params = new URLSearchParams({ path: rel, depth: String(depth) });
    const res = await this._requestJson("GET", `/v1/sessions/${sessionId}/files/list?${params.toString()}`);
    return res.entries;
  }

  async searchFiles(sessionId, pattern, { path: dirPath = "." } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(dirPath, { allowRoot: true });
    if (typeof pattern !== "string" || pattern.length === 0) {
      throw new TypeError("pattern must be non-empty");
    }
    const params = new URLSearchParams({ path: rel, pattern });
    const res = await this._requestJson("GET", `/v1/sessions/${sessionId}/files/search?${params.toString()}`);
    return res.entries;
  }

  async removeFile(sessionId, filePath, { recursive = false } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(filePath, { allowRoot: false });
    const params = new URLSearchParams({ path: rel });
    if (recursive) params.set("recursive", "true");
    return this._requestJson("DELETE", `/v1/sessions/${sessionId}/files?${params.toString()}`);
  }

  async sessionDiff(sessionId) {
    checkUuid(sessionId, "sessionId");
    return this._requestBytes("GET", `/v1/sessions/${sessionId}/diff`, { expectEtag: true });
  }

  async sessionSnapshot(sessionId, { path: relPath = ".", format = "tar", frozen = false, scope } = {}) {
    checkUuid(sessionId, "sessionId");
    const rel = checkRelativePath(relPath, { allowRoot: format === "tar" });
    const body = { path: rel, format };
    if (frozen) body.frozen = true;
    if (scope !== undefined) body.scope = scope;
    return this._requestBytes("POST", `/v1/sessions/${sessionId}/snapshot`, {
      jsonBody: body,
      expectEtag: true,
    });
  }

  async createVolume(options = {}) {
    const volId = options.id ? checkUuid(options.id, "volumeId") : randomUUID();
    const body = {
      id: volId,
      serverId: await this._ensureServerId(),
      profile: this._resolveProfile(options.profile),
    };
    if (options.cloneFrom !== undefined) body.cloneFrom = checkUuid(options.cloneFrom, "cloneFrom");
    if (options.byteLimit !== undefined) body.byteLimit = Math.trunc(options.byteLimit);
    if (options.inodeLimit !== undefined) body.inodeLimit = Math.trunc(options.inodeLimit);
    const created = await this._requestJson("POST", "/v1/volumes", {
      jsonBody: body,
      recoveryId: volId,
      uncertainOp: "createVolume",
    });
    if (options.wait === false || created.state === "ready") {
      return created;
    }
    return this.waitVolume(volId, { target: "ready" });
  }

  async getVolume(volumeId) {
    checkUuid(volumeId, "volumeId");
    return this._requestJson("GET", `/v1/volumes/${volumeId}`, { recoveryId: volumeId });
  }

  async listVolumes({ after } = {}) {
    const route = after
      ? `/v1/volumes?${new URLSearchParams({ after: checkUuid(after, "after") }).toString()}`
      : "/v1/volumes";
    return this._requestJson("GET", route);
  }

  async waitVolume(volumeId, { target = "ready", pollIntervalMs = 25, timeoutMs = 35000 } = {}) {
    checkUuid(volumeId, "volumeId");
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const vol = await this.getVolume(volumeId);
      if (vol.state === "closing") {
        throw new SandcrabError(503, "STORAGE_UNCERTAIN", volumeId);
      }
      if (vol.state === target) return vol;
      if (vol.state === "failed") {
        throw new SandcrabError(409, String(vol.code ?? "VOLUME_FAILED"), volumeId);
      }
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for volume ${volumeId}`);
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }

  async deleteVolume(volumeId, { forget = false } = {}) {
    checkUuid(volumeId, "volumeId");
    await this._requestJson("POST", `/v1/volumes/${volumeId}/delete`, { recoveryId: volumeId });
    const deleted = await this.waitVolume(volumeId, { target: "deleted" });
    if (forget) await this.forgetVolume(volumeId);
    return deleted;
  }

  async forgetVolume(volumeId) {
    checkUuid(volumeId, "volumeId");
    return this._requestJson("POST", `/v1/volumes/${volumeId}/forget`, { recoveryId: volumeId });
  }

  async importTemplate(archive, { profile, expectedId } = {}) {
    const prof = this._resolveProfile(profile);
    const params = new URLSearchParams({ profile: prof });
    if (expectedId !== undefined) {
      params.set("expectedId", checkDigest(expectedId, "expectedId"));
      const existing = await this.getTemplate(expectedId);
      if (existing) return existing;
    }
    try {
      return await this._requestJson("POST", `/v1/templates?${params.toString()}`, {
        streamBody: iterTarChunks(archive),
        headers: { "Content-Type": "application/x-tar", "Transfer-Encoding": "chunked" },
      });
    } catch (err) {
      if (expectedId !== undefined && !(err instanceof SandcrabError) && !(err instanceof ProtocolError)) {
        const found = await this.getTemplate(expectedId);
        if (found) return found;
        throw new PublicationUncertainError(expectedId);
      }
      throw err;
    }
  }

  async getTemplate(templateId) {
    checkDigest(templateId, "templateId");
    try {
      return await this._requestJson("GET", `/v1/templates/${templateId}`);
    } catch (err) {
      if (err instanceof SandcrabError && err.status === 404 && err.code === "TEMPLATE_NOT_FOUND") {
        return null;
      }
      throw err;
    }
  }

  async listTemplates({ after } = {}) {
    const route = after
      ? `/v1/templates?${new URLSearchParams({ after: checkDigest(after, "after") }).toString()}`
      : "/v1/templates";
    return this._requestJson("GET", route);
  }

  async composeTemplate(layers) {
    const expected = recipeId(layers);
    const ordered = [...layers];
    let existing = await this.getTemplate(expected);
    if (!existing) {
      try {
        existing = await this._requestJson("POST", "/v1/templates/compose", {
          jsonBody: { layers: ordered },
        });
      } catch (err) {
        if (!(err instanceof SandcrabError) && !(err instanceof ProtocolError)) {
          existing = await this.getTemplate(expected);
          if (!existing) throw new PublicationUncertainError(expected);
        } else {
          throw err;
        }
      }
    }
    if (
      existing.id !== expected ||
      !Array.isArray(existing.layers) ||
      existing.layers.length !== ordered.length ||
      existing.layers.some((layer, idx) => layer !== ordered[idx])
    ) {
      throw new ProtocolError("Published recipe differs from the requested layer order");
    }
    return existing;
  }

  async deleteTemplate(templateId) {
    checkDigest(templateId, "templateId");
    return this._requestJson("DELETE", `/v1/templates/${templateId}`);
  }
}
