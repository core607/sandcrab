package example.sandcrab;

import com.alibaba.opensandbox.sandbox.Sandbox;
import com.alibaba.opensandbox.sandbox.config.ConnectionConfig;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.Execution;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.RunCommandRequest;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.WriteEntry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.json.JsonMapper;

/** Calls the published Kotlin SDK with a pinned Sandcrab rootfs template. */
public final class SdkRootfs {
    private SdkRootfs() {}

    record Receipt(String result, String client, String sdkVersion, String sandboxId, List<String> commandIds) {}

    public static void main(String[] args) throws Exception {
        SdkConformance.require(args.length == 3, "Pass ENDPOINT TOKEN_FILE IMAGE");
        ConnectionConfig config = ConnectionConfig.builder()
                .domain(args[0])
                .protocol("http")
                .apiKey(Files.readString(Path.of(args[1])).strip())
                .requestTimeout(Duration.ofSeconds(15))
                .build();
        Sandbox sandbox = Sandbox.builder()
                .image(args[2])
                .connectionConfig(config)
                .resource(Map.of("cpu", "0.25", "memory", "32Mi"))
                .timeout(Duration.ofSeconds(60))
                .build();
        List<String> commands = new ArrayList<>();
        try {
            SdkConformance.require(sandbox.getInfo().getImage().getImage().equals(args[2]), "Image URI changed");
            Execution result = sandbox.commands()
                    .run(RunCommandRequest.builder()
                            .command("cat /opt/base; test ! -e /usr/bin/python3")
                            .build());
            commands.add(result.getId());
            SdkConformance.require(result.getExitCode() == 0, "Template command failed");
            SdkConformance.require(
                    SdkConformance.output(result).equals("template environment"), "Template content changed");
            sandbox.files()
                    .write(List.of(WriteEntry.builder()
                            .path("/workspace/sdk-file")
                            .data("kotlin rootfs")
                            .build()));
            SdkConformance.require(
                    sandbox.files().readFile("/workspace/sdk-file").equals("kotlin rootfs"), "File round trip failed");
        } finally {
            try {
                sandbox.kill();
            } finally {
                sandbox.close();
            }
        }
        System.out.println(JsonMapper.builder()
                .build()
                .writeValueAsString(new Receipt("PASS", "kotlin-sdk-java-caller", "1.1.0", sandbox.getId(), commands)));
    }
}
