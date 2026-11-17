import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import zlib from "node:zlib";

import {
  CommandFailedError,
  HostCallDispatcher,
  InMemoryReplyLedger,
  ProtocolError,
  SandcrabClient,
  TransportUncertainError,
  recipeId,
} from "../src/index.js";

const EPOCH = "00000000-0000-0000-0000-000000000100";
const RUN_ID = "00000000-0000-0000-0000-000000000101";
const SESSION_ID = "00000000-0000-0000-0000-000000000102";
const CALL_ID = "00000000-0000-0000-0000-000000000103";
const GUEST_ID = "00000000-0000-0000-0000-000000000104";
const STREAM_ID = "00000000-0000-0000-0000-000000000105";
const VOL_ID = "00000000-0000-0000-0000-000000000106";
const TOKEN = "d".repeat(64);

function sseFrame(id, event, data) {
  return `id: ${id}\nevent: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

async function withMockServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("transport, dual-env refusal and recipeId boundaries", () => {
  for (const bad of [
    "https://127.0.0.1:8080",
    "http://example.com:8080",
    "http://127.0.0.1",
    "http://127.0.0.1:8080/v1",
    "http://user@127.0.0.1:8080",
  ]) {
    assert.throws(() => new SandcrabClient({ endpoint: bad, token: TOKEN }), TypeError);
  }
  assert.throws(
    () =>
      new SandcrabClient({
        env: {
          SANDCRAB_SOCKET: "/run/sandcrab/sandcrab.sock",
          SANDCRAB_ENDPOINT: "http://127.0.0.1:8080",
        },
      }),
    /Both SANDCRAB_SOCKET and SANDCRAB_ENDPOINT/
  );
  const layers = ["a".repeat(64), "b".repeat(64)];
  assert.notEqual(recipeId(layers), recipeId([...layers].reverse()));
  assert.throws(() => recipeId([]), TypeError);
  assert.throws(() => recipeId([layers[0], layers[0]]), TypeError);
});

test("run, SSE output, session withSession auto-cleanup, files, volumes and gzip templates", async () => {
  const fileBytes = Buffer.from("line1\nline2\nline3\n", "utf8");
  const fileEtag = `"${createHash("sha256").update(fileBytes).digest("hex")}"`;
  let sessionClosed = false;
  let volDeleted = false;
  let importedTar = Buffer.alloc(0);
  const seenRoutes = [];

  await withMockServer(
    async (req, res) => {
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      const url = new URL(req.url, "http://127.0.0.1");
      seenRoutes.push(`${req.method} ${url.pathname}`);
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const bodyBuf = Buffer.concat(chunks);

      // Every native POST except streaming template import must carry a non-empty body.
      if (req.method === "POST" && url.pathname !== "/v1/templates") {
        assert.ok(bodyBuf.length > 0, `POST ${url.pathname} had empty body`);
      }

      if (url.pathname === "/v1/info") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ apiVersion: 1, serverId: EPOCH }));
      }
      if (req.method === "POST" && url.pathname === "/v1/runs") {
        const parsed = JSON.parse(bodyBuf.toString());
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: parsed.id, state: "running" }));
      }
      if (url.pathname === `/v1/runs/${RUN_ID}/events`) {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.write(sseFrame(`${STREAM_ID}:0:0`, "state", { state: "running" }));
        res.write(
          sseFrame(`${STREAM_ID}:6:0`, "stdout", {
            offset: 0,
            base64: Buffer.from("hello\n").toString("base64"),
          })
        );
        res.end(sseFrame(`${STREAM_ID}:6:0`, "result", { state: "succeeded" }));
        return;
      }
      if (req.method === "GET" && url.pathname === `/v1/runs/${RUN_ID}`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            id: RUN_ID,
            state: "succeeded",
            result: { exitCode: 0, stdout: "hello\n", stderr: "" },
          })
        );
      }
      if (req.method === "POST" && url.pathname === `/v1/runs/${RUN_ID}/forget`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ forgotten: true }));
      }
      if (req.method === "POST" && url.pathname === "/v1/sessions") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: SESSION_ID, state: "starting" }));
      }
      if (req.method === "GET" && url.pathname === `/v1/sessions/${SESSION_ID}`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            id: SESSION_ID,
            serverId: EPOCH,
            profile: "default",
            state: sessionClosed ? "closed" : "ready",
          })
        );
      }
      if (req.method === "POST" && url.pathname === `/v1/sessions/${SESSION_ID}/close`) {
        sessionClosed = true;
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: SESSION_ID, state: "closed" }));
      }
      if (req.method === "POST" && url.pathname === `/v1/sessions/${SESSION_ID}/forget`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ forgotten: true }));
      }
      if (req.method === "PUT" && url.pathname === `/v1/sessions/${SESSION_ID}/files`) {
        assert.equal(url.searchParams.get("parents"), "true");
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ path: url.searchParams.get("path"), bytes: bodyBuf.length }));
      }
      if (req.method === "GET" && url.pathname === `/v1/sessions/${SESSION_ID}/files`) {
        if (req.headers.range) {
          assert.equal(req.headers.range, "bytes=0-4");
          res.writeHead(206, { "X-Sandcrab-Server-Id": EPOCH });
          return res.end(fileBytes.subarray(0, 5));
        }
        if (url.searchParams.get("offset")) {
          res.writeHead(200, { "X-Sandcrab-Server-Id": EPOCH });
          return res.end(Buffer.from("line2"));
        }
        res.writeHead(200, { ETag: fileEtag, "X-Sandcrab-Server-Id": EPOCH });
        return res.end(fileBytes);
      }
      if (req.method === "POST" && url.pathname === `/v1/sessions/${SESSION_ID}/files/mkdir`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ path: "src" }));
      }
      if (req.method === "GET" && url.pathname === `/v1/sessions/${SESSION_ID}/files/list`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ entries: [{ path: "src/a.txt", kind: "file" }] }));
      }
      if (req.method === "GET" && url.pathname === `/v1/sessions/${SESSION_ID}/files/search`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ entries: [{ path: "src/a.txt", kind: "file" }] }));
      }
      if (req.method === "DELETE" && url.pathname === `/v1/sessions/${SESSION_ID}/files`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ removed: true }));
      }
      if (req.method === "POST" && url.pathname === "/v1/volumes") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: VOL_ID, state: "creating" }));
      }
      if (req.method === "GET" && url.pathname === `/v1/volumes/${VOL_ID}`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: VOL_ID, state: volDeleted ? "deleted" : "ready" }));
      }
      if (req.method === "POST" && url.pathname === `/v1/volumes/${VOL_ID}/delete`) {
        volDeleted = true;
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: VOL_ID, state: "deleting" }));
      }
      if (req.method === "POST" && url.pathname === `/v1/volumes/${VOL_ID}/forget`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ forgotten: true }));
      }
      if (req.method === "POST" && url.pathname === "/v1/templates") {
        importedTar = bodyBuf;
        const digest = createHash("sha256").update(bodyBuf).digest("hex");
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: digest }));
      }
      res.writeHead(404);
      res.end(JSON.stringify({ error: { code: "NOT_FOUND" } }));
    },
    async (endpoint) => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sandcrab-ts-test-"));
      const tokenFile = path.join(tmp, "client.token");
      fs.writeFileSync(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
      const client = new SandcrabClient({ endpoint, tokenFile, defaultProfile: "default" });
      try {
        const streamed = [];
        const runRes = await client.run(["echo", "hello"], {
          id: RUN_ID,
          onOutput: (kind, chunk) => streamed.push([kind, chunk.toString()]),
          check: true,
        });
        assert.equal(runRes.result.stdout, "hello\n");
        assert.deepEqual(streamed, [["stdout", "hello\n"]]);

        const vol = await client.createVolume({ id: VOL_ID });
        assert.equal(vol.state, "ready");
        await client.deleteVolume(VOL_ID, { forget: true });

        const rawTar = Buffer.from("tar-archive-payload-for-sandcrab".repeat(32));
        const gzPath = path.join(tmp, "rootfs.tar.gz");
        fs.writeFileSync(gzPath, zlib.gzipSync(rawTar));
        const tpl = await client.importTemplate(gzPath);
        assert.ok(importedTar.equals(rawTar));
        assert.equal(tpl.id, createHash("sha256").update(rawTar).digest("hex"));

        await client.withSession({ id: SESSION_ID }, async (session) => {
          await session.mkdir("src");
          await session.writeFile("src/a.txt", fileBytes, { parents: true });
          assert.ok((await session.readFile("src/a.txt")).equals(fileBytes));
          assert.equal((await session.readFile("src/a.txt", { byteRange: { start: 0, end: 4 } })).toString(), "line1");
          assert.equal(await session.readText("src/a.txt", { offset: 2, limit: 1 }), "line2");
          assert.equal((await session.listFiles("src")).length, 1);
          assert.equal((await session.searchFiles("*.txt")).length, 1);
          await session.removeFile("src/a.txt");
          await assert.rejects(() => session.readFile("../escape"), TypeError);
        });
        assert.ok(seenRoutes.includes(`POST /v1/sessions/${SESSION_ID}/close`));
        assert.ok(seenRoutes.includes(`POST /v1/sessions/${SESSION_ID}/forget`));
      } finally {
        client.close();
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    }
  );
});

test("HostCallDispatcher ledger, reconnect, cancel on unauthorized and TransportUncertainError", async () => {
  const key = Buffer.alloc(32, 7);
  const digest = createHash("sha256").update("artifact").digest("hex");
  const ledger = new InMemoryReplyLedger();
  const dispatcher = new HostCallDispatcher({ ledger });
  let handlerCalls = 0;

  dispatcher.onJson("sign-sha256", async (req) => {
    handlerCalls += 1;
    if (req.digest !== digest) throw new Error("unauthorized digest");
    return {
      signature: createHmac("sha256", key).update(Buffer.from(digest, "hex")).digest("hex"),
    };
  });

  const payload = Buffer.from(JSON.stringify({ operation: "sign-sha256", digest }));
  const payloadSha = createHash("sha256").update(payload).digest("hex");
  let streamCount = 0;
  let cancelled = false;
  let dropSubmit = false;

  await withMockServer(
    async (req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      for await (const _ of req) {
        // drain
      }
      if (url.pathname === "/v1/info") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ apiVersion: 1, serverId: EPOCH }));
      }
      if (req.method === "POST" && url.pathname === "/v1/runs") {
        if (dropSubmit) {
          req.socket.destroy();
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: RUN_ID, state: "running" }));
      }
      if (url.pathname === `/v1/runs/${RUN_ID}/calls/events`) {
        streamCount += 1;
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        if (streamCount === 1) {
          res.write(sseFrame(`${STREAM_ID}:0`, "state", { runId: RUN_ID, serverId: EPOCH }));
          return res.end(sseFrame(`${STREAM_ID}:0`, "error", { code: "OBSERVATION_TIMEOUT" }));
        }
        if (streamCount === 2) {
          assert.equal(req.headers["last-event-id"], `${STREAM_ID}:0`);
          const callObj = {
            id: CALL_ID,
            requestId: GUEST_ID,
            sequence: 1,
            requestSha256: payloadSha,
            base64: payload.toString("base64"),
          };
          res.write(sseFrame(`${STREAM_ID}:0`, "state", { runId: RUN_ID, serverId: EPOCH }));
          res.write(sseFrame(`${STREAM_ID}:1`, "call", callObj));
          res.write(sseFrame(`${STREAM_ID}:1`, "call", callObj));
          return res.end(sseFrame(`${STREAM_ID}:1`, "result", { run: { id: RUN_ID, state: "succeeded" } }));
        }
        const badPayload = Buffer.from(JSON.stringify({ operation: "forbidden" }));
        res.write(sseFrame(`${STREAM_ID}:0`, "state", { runId: RUN_ID, serverId: EPOCH }));
        return res.end(
          sseFrame(`${STREAM_ID}:1`, "call", {
            id: CALL_ID,
            requestId: GUEST_ID,
            sequence: 1,
            requestSha256: createHash("sha256").update(badPayload).digest("hex"),
            base64: badPayload.toString("base64"),
          })
        );
      }
      if (req.method === "POST" && url.pathname === `/v1/runs/${RUN_ID}/calls/${CALL_ID}/reply`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: CALL_ID, state: "replied" }));
      }
      if (req.method === "GET" && url.pathname === `/v1/runs/${RUN_ID}`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: RUN_ID, state: "failed", result: { exitCode: 1 } }));
      }
      if (req.method === "POST" && url.pathname === `/v1/runs/${RUN_ID}/forget`) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ forgotten: true }));
      }
      if (req.method === "POST" && url.pathname === `/v1/runs/${RUN_ID}/cancel`) {
        cancelled = true;
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: RUN_ID, state: "cancelled" }));
      }
      res.writeHead(404);
      res.end();
    },
    async (endpoint) => {
      const client = new SandcrabClient({ endpoint, token: TOKEN, defaultProfile: "python" });
      try {
        await assert.rejects(
          () => client.run(["python3", "-c", "pass"], { id: RUN_ID, dispatcher, check: true }),
          CommandFailedError
        );
        assert.equal(handlerCalls, 1);

        await assert.rejects(
          () => client.run(["python3", "-c", "pass"], { id: RUN_ID, dispatcher: new HostCallDispatcher() }),
          /No host-call handler registered/
        );
        assert.equal(cancelled, true);

        dropSubmit = true;
        await assert.rejects(
          () => client.submitRun(["true"], { id: RUN_ID }),
          (err) => err instanceof TransportUncertainError && err.recoveryId === RUN_ID
        );
      } finally {
        client.close();
      }
    }
  );
});
