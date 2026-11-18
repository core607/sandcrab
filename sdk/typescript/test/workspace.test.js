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
