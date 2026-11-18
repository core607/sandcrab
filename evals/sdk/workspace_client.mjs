import { createInterface } from "node:readline";
import { SandcrabClient } from "sandcrab";

const client = new SandcrabClient();
try {
  const base = await client.importTemplate(process.argv[3], { profile: "default" });
  const tools = await client.workspaceTools(process.argv[2], { profile: "default", templateId: base.id, freshChild: true });
  console.log(JSON.stringify(tools.schemas));
  for await (const line of createInterface({ input: process.stdin })) {
    const { name, arguments: args } = JSON.parse(line);
    if (name === "checkpoint") {
      console.log(JSON.stringify((await tools.checkpoint()).toString("base64")));
      continue;
    }
    if (name === "dispose") {
      await tools.dispose();
      await client.deleteTemplate(base.id);
      console.log("true");
      break;
    }
    console.log(JSON.stringify(await tools.handlers[name](args)));
  }
} finally {
  client.close();
}
