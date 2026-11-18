import { createInterface } from "node:readline";
import { SandcrabClient } from "sandcrab";

const client = new SandcrabClient();
try {
  const tools = await client.workspaceTools(process.argv[2], { profile: "default" });
  console.log(JSON.stringify(tools.schemas));
  for await (const line of createInterface({ input: process.stdin })) {
    const { name, arguments: args } = JSON.parse(line);
    if (name === "dispose") {
      await tools.dispose();
      console.log("true");
      break;
    }
    console.log(JSON.stringify(await tools.handlers[name](args)));
  }
} finally {
  client.close();
}
