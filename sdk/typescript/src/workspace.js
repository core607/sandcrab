import { randomUUID } from "node:crypto";
import { checkDigest, checkProfile, checkRelativePath, checkUuid, ProtocolError, SandcrabError, TransportUncertainError } from "./index.js";

const TEXT_BYTES = 16384;
const TRUNCATED = "\n[truncated]";
const toolNames = new Set(["exec", "read_file", "write_file", "edit_file", "list_dir", "search"]);
const unknownOutcome = () => ({ ok: false, code: "OUTCOME_UNKNOWN", message: "Inspect the workspace before submitting another write." });
const delay = () => new Promise(resolve => setTimeout(resolve, 25));

function clip(text) {
  const raw = Buffer.from(text);
  if (raw.length <= TEXT_BYTES) return [text, false];
  return [new TextDecoder().decode(raw.subarray(0, TEXT_BYTES), { stream: true }) + TRUNCATED, true];
}

function validate(schema, args) {
  if (!args || typeof args !== "object" || Array.isArray(args) || !schema.required.every(key => Object.hasOwn(args, key))) {
    throw new TypeError("Invalid tool arguments");
  }
  for (const [key, value] of Object.entries(args)) {
    const spec = Object.hasOwn(schema.properties, key) && schema.properties[key];
    if (!spec) throw new TypeError("Unknown tool argument");
    if (spec.type === "integer") {
      if (!Number.isSafeInteger(value) || value < (spec.minimum ?? 0) || value > (spec.maximum ?? Number.MAX_SAFE_INTEGER)) throw new TypeError("Invalid " + key);
    } else if (typeof value !== spec.type || (typeof value === "string" && ([...value].length < (spec.minLength ?? 0) || [...value].length > (spec.maxLength ?? 65536)))) {
      throw new TypeError("Invalid " + key);
    }
  }
}

export async function bindWorkspaceTools(client, key, { profile, templateId, freshChild = false } = {}) {
  if (typeof key !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(key)) throw new TypeError("Invalid workspace key");
  const route = "/v1/workspaces/" + key;
  if (typeof freshChild !== "boolean") throw new TypeError("freshChild must be a boolean");
  const plan = { profile: checkProfile(profile ?? client.defaultProfile ?? "default") };
  if (templateId !== undefined) plan.templateId = checkDigest(templateId);
  let record = await client._requestJson("POST", route, { jsonBody: plan });
  const generation = checkUuid(record.generation, "generation");
  const until = Date.now() + 35000;
  while (record.state === "creating" && Date.now() < until) {
    await delay();
    record = await client._requestJson("GET", route);
  }
  if (record.state !== "ready" || record.generation !== generation) throw new SandcrabError(409, "WORKSPACE_NOT_READY");
  const catalog = await client._requestJson("GET", "/v1/workspace-tools");
  return new WorkspaceTools(client, route, generation, catalog.tools, freshChild);
}

class WorkspaceTools {
  constructor(client, route, generation, schemas, freshChild = false) {
    this.freshChild = freshChild;
    this.client = client;
    this.route = route;
    this.generation = generation;
    this.schemas = schemas.filter(tool => toolNames.has(tool.name));
    this.inputs = new Map(this.schemas.map(tool => [tool.name, tool.inputSchema]));
    this.handlers = Object.fromEntries(this.schemas.map(tool => [tool.name, args => this.call(tool.name, args)]));
  }

  async call(name, args) {
    if (!this.inputs.has(name)) return { ok: false, code: "UNKNOWN_TOOL" };
    try {
      validate(this.inputs.get(name), args);
      const until = Date.now() + 5000;
      for (;;) {
        try {
          return name === "exec" ? await this.exec(args) : await this.file(name, args);
        } catch (error) {
          if (!(error instanceof SandcrabError) || !["WORKSPACE_REOPENING", "SESSION_FILES_BUSY", "WORKSPACE_SUBMISSION_EXPIRED"].includes(error.code) || Date.now() >= until) throw error;
          await delay();
        }
      }
    } catch (error) {
      if (error instanceof TransportUncertainError) return unknownOutcome();
      if (error instanceof SandcrabError) {
        if (error.code === "EDIT_CONFLICT") return { ok: false, code: "EDIT_CONFLICT" };
        if (error.code === "EDIT_MATCH_COUNT") return { ok: false, code: "EDIT_CONFLICT", message: "Read the file and choose one exact match." };
        if (error.status === 404) return { ok: false, code: "NOT_FOUND" };
        if (error.status === 429 || ["WORKSPACE_REOPENING", "SESSION_FILES_BUSY"].includes(error.code)) return { ok: false, code: "BUSY" };
        if (error.status === 413) return { ok: false, code: "LIMIT" };
        if (["exec", "write_file", "edit_file"].includes(name) && (error.status >= 500 || /UNKNOWN|UNCONFIRMED/.test(error.code))) return unknownOutcome();
        return { ok: false, code: "REFUSED" };
      }
      if (error instanceof TypeError || error instanceof RangeError) return { ok: false, code: "INVALID_ARGUMENTS" };
      if (error instanceof ProtocolError || error.code || error.name === "AbortError") return { ok: false, code: "TRANSPORT_ERROR" };
      throw error;
    }
  }

  async exec(args) {
    const current = await this.client._requestJson("GET", this.route);
    if (current.generation !== this.generation) throw new SandcrabError(409, "WORKSPACE_CHANGED");
    const id = randomUUID();
    const jsonBody = { ...args, id, serverId: current.serverId, generation: this.generation, submissionWindow: current.submissionWindow };
    if (this.freshChild) jsonBody.freshChild = true;
    await this.client._requestJson("POST", this.route + "/commands", { jsonBody, recoveryId: id, uncertainOp: "workspace command" });
    let run;
    try {
      run = await this.client.waitRun(id);
    } catch (error) {
      throw new TransportUncertainError("workspace command", id, error);
    }
    const result = run.result ?? {};
    if (result.executed === false) return { ok: false, code: "REFUSED" };
    const [stdout, outCut] = clip(result.stdout ?? "");
    const [stderr, errCut] = clip(result.stderr ?? "");
    const out = { ok: run.state === "succeeded", stdout, stderr, exitCode: result.exitCode ?? null, freshShell: run.freshShell, truncated: result.truncated === true || outCut || errCut };
    if (!out.ok) out.code = ["timeout", "timed_out"].includes(run.state) ? "TIMEOUT" : "COMMAND_FAILED";
    return out;
  }

  async file(name, args) {
    const file = checkRelativePath(args.path ?? ".", { allowRoot: name === "list_dir" || name === "search" });
    const route = this.route + "/files";
    const headers = { "X-Sandcrab-Workspace-Generation": this.generation };
    if (name === "read_file") return this.read(route, file, args, headers);
    if (name === "write_file") {
      const rawBody = Buffer.from(args.content);
      if (rawBody.length > 32768) throw new RangeError("Content exceeds tool limit");
      const query = new URLSearchParams({ path: file, parents: String(args.parents ?? true), replace: String(args.replace ?? true) });
      const reply = await this.client._requestJson("PUT", route + "?" + query, { headers, rawBody, recoveryId: file, uncertainOp: "write file" });
      return { ok: true, bytes: reply.bytes, version: reply.sha256 };
    }
    if (name === "edit_file") {
      const jsonBody = { path: file, expectedSha256: checkDigest(args.version), old: args.old, new: args.new };
      const reply = await this.client._requestJson("POST", route + "/edit", { headers, jsonBody, recoveryId: file, uncertainOp: "edit file" });
      return { ok: true, replacedCount: reply.replacedCount };
    }
    const query = new URLSearchParams({ path: file });
    const action = name === "list_dir" ? "list" : "search";
    if (name === "list_dir") query.set("depth", String(args.depth ?? 1));
    else {
      query.set("pattern", args.pattern ?? "*");
      if (args.contains !== undefined) query.set("contains", args.contains);
    }
    const reply = await this.client._requestJson("GET", route + "/" + action + "?" + query, { headers });
    const entries = [];
    let budget = TEXT_BYTES;
    for (const { path, type, size } of reply.entries) {
      const bytes = Buffer.byteLength(path) + 64;
      if (bytes > budget || entries.length === 128) break;
      entries.push({ path, type, size });
      budget -= bytes;
    }
    return { ok: true, entries, truncated: entries.length !== reply.entries.length };
  }

  async checkpoint() {
    return this.client._requestBytes("GET", this.route + "/diff", {
      headers: { "X-Sandcrab-Workspace-Generation": this.generation }, expectEtag: true,
    });
  }

  async dispose() {
    const jsonBody = { generation: this.generation };
    await this.client._requestJson("POST", this.route + "/delete", { jsonBody });
    const until = Date.now() + 65000;
    while (Date.now() < until) {
      const current = await this.client._requestJson("GET", this.route);
      if (current.generation !== this.generation) throw new SandcrabError(409, "WORKSPACE_CHANGED");
      if (current.state === "deleted") {
        await this.client._requestJson("POST", this.route + "/forget", { jsonBody });
        return;
      }
      if (current.state !== "deleting") throw new SandcrabError(409, "WORKSPACE_CLEANUP_UNCONFIRMED");
      await delay();
    }
    throw new Error("Workspace deletion did not finish");
  }

  async read(route, file, args, headers) {
    const query = new URLSearchParams({ path: file });
    headers["X-Sandcrab-Read-Version"] = "sha256";
    const asBytes = args.byteStart !== undefined || args.byteEnd !== undefined;
    const lines = args.limit ?? 200;
    if (asBytes) {
      const start = args.byteStart ?? 0;
      const end = args.byteEnd ?? start + TEXT_BYTES - 1;
      if (end < start || args.offset !== undefined || args.limit !== undefined) throw new TypeError("Choose one file range");
      headers.Range = "bytes=" + start + "-" + Math.min(end, start + TEXT_BYTES);
    } else {
      query.set("offset", String(args.offset ?? 1));
      query.set("limit", String(args.limit ?? 201));
      query.set("maxBytes", String(TEXT_BYTES + 1));
    }
    const response = await this.client._openRawRequest("GET", route + "?" + query, { headers });
    const chunks = [];
    let size = 0;
    for await (const chunk of response) {
      if (size >= TEXT_BYTES + 1) continue;
      const selected = chunk.subarray(0, TEXT_BYTES + 1 - size);
      chunks.push(selected);
      size += selected.length;
    }
    const buf = Buffer.concat(chunks);
    if (response.statusCode >= 400) {
      let code = "API_ERROR";
      try { code = JSON.parse(buf).error.code; } catch { /* Status still identifies a refusal. */ }
      throw new SandcrabError(response.statusCode, code);
    }
    if (response.statusCode !== (asBytes ? 206 : 200)) throw new ProtocolError("Unexpected file selection response");
    const version = response.headers["x-sandcrab-file-sha256"] ?? null;
    if (version !== null) checkDigest(version);
    let truncated = size > TEXT_BYTES;
    const data = buf.subarray(0, TEXT_BYTES);
    if (asBytes) return { ok: true, content: data.toString("base64"), encoding: "base64", version, truncated };
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data, { stream: truncated });
    } catch {
      return { ok: false, code: "BINARY_FILE", message: "Use a byte range to read binary content." };
    }
    const rows = text.split("\n");
    truncated ||= args.limit === undefined && rows.length > lines;
    return { ok: true, content: rows.slice(0, lines).join("\n") + (truncated ? TRUNCATED : ""), encoding: "utf-8", version, truncated };
  }
}
