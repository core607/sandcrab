import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { SandcrabClient } from "../src/index.js";

test("workspace tool reports a lost command reply without replay", async () => {
  const serverId = "11111111-1111-4111-8111-111111111111";
  const generation = "22222222-2222-4222-8222-222222222222";
  let submissions = 0;
  const server = http.createServer((req, res) => {
    if (req.url.endsWith("/commands")) {
      submissions += 1;
      req.socket.destroy();
      return;
    }
    const inputSchema = { type: "object", properties: { command: { type: "string" } }, required: ["command"] };
    const result = req.url === "/v1/workspace-tools"
      ? { tools: ["exec", "future_tool"].map(name => ({ name, inputSchema })) }
      : { state: "ready", generation, serverId, submissionWindow: 0 };
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const client = new SandcrabClient({ endpoint: "http://127.0.0.1:" + server.address().port, token: "d".repeat(64) });
  try {
    const tools = await client.workspaceTools("example");
    assert.deepEqual(Object.keys(tools.handlers), ["exec"]);
    const reply = await tools.call("exec", { command: "printf x >> record" });
    assert.equal(reply.code, "OUTCOME_UNKNOWN");
    assert.equal(reply.ok, false);
    assert.equal(submissions, 1);
  } finally {
    client.close();
    await new Promise(resolve => server.close(resolve));
  }
});

test("unusable write receipts leave the outcome unknown", async () => {
  const digest = "0".repeat(64);
  const args = {
    exec: { command: "printf x >> note" },
    write_file: { path: "note", content: "x" },
    edit_file: { path: "note", version: digest, old: "x", new: "y" },
  };
  const catalog = Object.entries(args).map(([name, input]) => ({
    name, inputSchema: { required: Object.keys(input),
      properties: Object.fromEntries(Object.keys(input).map(key => [key, { type: "string" }])) },
  }));
  let reply;
  let mutations = 0;
  const server = http.createServer((req, res) => {
    const path = req.url.split("?")[0];
    if (["files", "edit", "commands"].includes(path.split("/").at(-1))) {
      mutations += 1;
      res.writeHead(reply.status);
      res.end(reply.body);
      return;
    }
    res.end(JSON.stringify(path === "/v1/workspace-tools" ? { tools: catalog } : {
      state: "ready", submissionWindow: 0, serverId: "11111111-1111-4111-8111-111111111111",
      generation: "22222222-2222-4222-8222-222222222222",
    }));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const client = new SandcrabClient({ endpoint: "http://127.0.0.1:" + server.address().port, token: "d".repeat(64) });
  try {
    const tools = await client.workspaceTools("example");
    for (const [name, status, body] of [
      ["exec", 202, "{"],
      ["write_file", 200, "{}"],
      ["write_file", 200, JSON.stringify({ path: "note", bytes: 1, sha256: digest })],
      ["edit_file", 200, JSON.stringify({ path: "other", replacedCount: 1 })],
      ["edit_file", 200, JSON.stringify({ path: "note", replacedCount: 0 })],
    ]) {
      reply = { status, body };
      const before = mutations;
      const result = await tools.call(name, args[name]);
      assert.equal(result.ok, false);
      assert.equal(result.code, "OUTCOME_UNKNOWN");
      assert.equal(mutations, before + 1);
    }
    reply = { status: 409, body: JSON.stringify({ error: { code: "EDIT_CONFLICT" } }) };
    assert.deepEqual(await tools.call("edit_file", args.edit_file), { ok: false, code: "EDIT_CONFLICT" });
  } finally {
    client.close();
    await new Promise(resolve => server.close(resolve));
  }
});
