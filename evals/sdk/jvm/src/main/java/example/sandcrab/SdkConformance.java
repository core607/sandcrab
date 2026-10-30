package example.sandcrab;

import com.alibaba.opensandbox.sandbox.Sandbox;
import com.alibaba.opensandbox.sandbox.SandboxManager;
import com.alibaba.opensandbox.sandbox.config.ConnectionConfig;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.Execution;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.OutputMessage;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.RunCommandRequest;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.ContentReplaceEntry;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.MoveEntry;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.SearchEntry;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.SetPermissionEntry;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.WriteEntry;
import com.alibaba.opensandbox.sandbox.domain.models.sandboxes.SandboxFilter;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import tools.jackson.databind.json.JsonMapper;

/** Calls the published Kotlin SDK from an independent Java consumer. */
public final class SdkConformance {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String SDK_SHA = "cb96348a273124a899586e23abe9b5aeafcc98b1d6055532a62ecc8a2a22a392";

    private SdkConformance() {}

    record Created(String created) {}

    record Receipt(
            String result,
            String client,
            String sdkVersion,
            String sdkArtifactSha256,
            List<String> checks,
            List<String> sandboxIds,
            List<String> commandIds,
            List<String> contextIds) {}

    public static void main(String[] args) throws Exception {
        require(args.length == 3, "Pass ENDPOINT TOKEN_FILE barrier-or-direct");
        String digest = sdkDigest();
        String token = Files.readString(Path.of(args[1])).strip();
        ConnectionConfig config = ConnectionConfig.builder()
                .domain(args[0])
                .protocol("http")
                .apiKey(token)
                .requestTimeout(Duration.ofSeconds(15))
                .build();
        List<String> checks = new ArrayList<>();
        List<String> commands = new ArrayList<>();
        Map<String, String> metadata = Map.of("name", "SDK proof 汉字 & +", "client", "kotlin-java");
        try (SandboxManager manager =
                SandboxManager.builder().connectionConfig(config).build()) {
            Sandbox sandbox = Sandbox.builder()
                    .image("python")
                    .connectionConfig(config)
                    .resource(Map.of("cpu", "0.25", "memory", "32Mi"))
                    .timeout(Duration.ofSeconds(60))
                    .env("SDK_VALUE", "base ' quoted")
                    .metadata(metadata)
                    .build();
            boolean deleted = false;
            try {
                barrier(args[2], sandbox.getId());
                lifecycle(sandbox, manager, metadata, token, checks);
                commands(sandbox, commands, checks);
                List<String> contexts = SdkContexts.exercise(sandbox, commands, checks);
                files(sandbox, commands, checks);
                directories(sandbox, commands, checks);
                sandbox.renew(Duration.ofSeconds(90));
                sandbox.kill();
                deleted = true;
                checks.add("renew-and-explicit-delete");
                System.out.println(JSON.writeValueAsString(new Receipt(
                        "PASS",
                        "kotlin-sdk-java-caller",
                        "1.1.0",
                        digest,
                        checks,
                        List.of(sandbox.getId()),
                        commands,
                        contexts)));
            } finally {
                try {
                    if (!deleted) {
                        sandbox.kill();
                    }
                } finally {
                    sandbox.close();
                }
            }
        }
    }

    private static void barrier(String mode, String id) throws Exception {
        if (mode.equals("barrier")) {
            System.out.println(JSON.writeValueAsString(new Created(id)));
            System.out.flush();
            String line = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
            require("continue".equals(line), "Kernel inspection barrier was not released");
        } else {
            require(mode.equals("direct"), "Unknown barrier mode");
        }
    }

    private static void lifecycle(
            Sandbox sandbox, SandboxManager manager, Map<String, String> metadata, String token, List<String> checks) {
        require(sandbox.getInfo().getId().equals(sandbox.getId()), "Sandbox identity changed");
        require(sandbox.getInfo().getStatus().getState().equals("Running"), "Sandbox is not ready");
        require(sandbox.getInfo().getMetadata().equals(metadata), "Metadata did not round-trip");
        require(sandbox.isHealthy(), "SDK health probe failed");
        String access = sandbox.getEndpoint(44772).getHeaders().get("X-EXECD-ACCESS-TOKEN");
        require(access.length() == 64, "Endpoint access token is missing");
        require(!access.equals(token), "Endpoint exposed the lifecycle credential");
        require(
                manager
                        .listSandboxInfos(SandboxFilter.builder()
                                .states("Running")
                                .metadata(metadata)
                                .page(1)
                                .pageSize(5)
                                .build())
                        .getSandboxInfos()
                        .stream()
                        .map(item -> item.getId())
                        .toList()
                        .equals(List.of(sandbox.getId())),
                "Filtered discovery disagreed");
        checks.add("create-discover-filter-and-scope-endpoint-credentials");
    }

    private static void commands(Sandbox sandbox, List<String> ids, List<String> checks) {
        Execution execution = sandbox.commands()
                .run(RunCommandRequest.builder()
                        .argv(List.of(
                                "python3",
                                "-c",
                                "import os,sys; print(os.environ['SDK_VALUE']); sys.stderr.write('diagnostic\\n')"))
                        .build());
        remember(execution, ids, 0);
        require(output(execution).equals("base ' quoted\n"), "Command environment or output changed");
        require(
                execution.getLogs().getStderr().stream()
                        .map(OutputMessage::getText)
                        .collect(Collectors.joining())
                        .equals("diagnostic\n"),
                "Stderr did not survive the stream");
        require(
                sandbox.commands().getCommandStatus(execution.getId()).getExitCode() == 0,
                "Completed status is missing");
        checks.add("foreground-argv-environment-output-and-retained-status");
        execution = sandbox.commands()
                .run(RunCommandRequest.builder()
                        .argv(List.of(
                                "python3",
                                "-c",
                                "import sys; sys.stdout.buffer.write(b'A'*4095+'中'.encode()+b'\\xffX')"))
                        .build());
        remember(execution, ids, 0);
        require(output(execution).equals("A".repeat(4095) + "中\ufffdX"), "UTF-8 boundaries changed output");
        execution = sandbox.commands().run("printf failed; exit 7");
        remember(execution, ids, 7);
        require(execution.getError() != null, "Failed command has no SDK error");
        require(output(execution).equals("failed"), "Failed command lost output");
        checks.add("split-unicode-invalid-bytes-and-failed-exit");
        for (int index = 0; index < 16; index++) {
            execution = sandbox.commands().run("printf " + index);
            remember(execution, ids, 0);
            require(output(execution).equals(Integer.toString(index)), "Command output changed");
        }
        checks.add("bounded-native-result-reclamation");
    }

    private static String sdkDigest() throws Exception {
        Path artifact = Path.of(Sandbox.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI());
        String digest =
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact)));
        require(SDK_SHA.equals(digest), "Unexpected Kotlin SDK artifact");
        return digest;
    }

    static String output(Execution execution) {
        return execution.getLogs().getStdout().stream()
                .map(OutputMessage::getText)
                .collect(Collectors.joining());
    }

    private static void files(Sandbox sandbox, List<String> ids, List<String> checks) throws Exception {
        byte[] bytes = new byte[131328];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) index;
        }
        sandbox.files()
                .write(List.of(
                        WriteEntry.builder()
                                .path("/workspace/文件; name=odd.bin")
                                .data(bytes)
                                .mode(640)
                                .build(),
                        WriteEntry.builder()
                                .path("/workspace/empty")
                                .data(new byte[0])
                                .build(),
                        WriteEntry.builder()
                                .path("/workspace/text")
                                .data("hello 世界\n")
                                .build()));
        require(
                Arrays.equals(bytes, sandbox.files().readByteArray("/workspace/文件; name=odd.bin")),
                "Binary content changed");
        require(sandbox.files().readByteArray("/workspace/empty").length == 0, "Empty file changed");
        require(sandbox.files().readFile("/workspace/text").equals("hello 世界\n"), "Text content changed");
        try (var stream = sandbox.files().readStream("/workspace/文件; name=odd.bin")) {
            require(Arrays.equals(bytes, stream.readAllBytes()), "Streaming download changed bytes");
        }
        try (var input = new ByteArrayInputStream(bytes)) {
            sandbox.files()
                    .writeFile(WriteEntry.builder()
                            .path("/workspace/文件; name=odd.bin")
                            .data(input)
                            .mode(600)
                            .build());
        }
        Execution execution = sandbox.commands()
                .run(RunCommandRequest.builder()
                        .argv(List.of(
                                "python3",
                                "-c",
                                "from pathlib import Path; import stat; p=Path('/workspace/文件; name=odd.bin'); "
                                        + "assert p.read_bytes()==bytes(range(256))*513; "
                                        + "assert stat.S_IMODE(p.stat().st_mode)==0o600; print('files verified')"))
                        .build());
        remember(execution, ids, 0);
        require(output(execution).equals("files verified\n"), "Sandbox-side file checks failed");
        checks.add("fixed-and-chunked-multipart-binary-text-empty-stream-and-replacement-mode");
    }

    private static void directories(Sandbox sandbox, List<String> ids, List<String> checks) {
        sandbox.files()
                .createDirectories(List.of(
                        WriteEntry.builder()
                                .path("/workspace/project/src")
                                .mode(700)
                                .build(),
                        WriteEntry.builder().path("project").mode(750).build()));
        sandbox.files()
                .writeFile(WriteEntry.builder()
                        .path("project/src/main.txt")
                        .data("original")
                        .mode(600)
                        .build());
        var info = sandbox.files().readFileInfo(List.of("project", "/workspace/project/src", "project/src/main.txt"));
        require(
                info.get("project").getMode() == 750 && info.get("project").getSize() == 0,
                "Directory mode or size changed");
        require(
                info.get("/workspace/project/src").getMode() == 700
                        && info.get("project/src/main.txt").getSize() == 8,
                "Nested metadata changed");
        require(
                sandbox.files().listDirectory("project", 2).stream()
                        .map(item -> item.getPath())
                        .toList()
                        .equals(List.of("/workspace/project/src", "/workspace/project/src/main.txt")),
                "Listing order changed");
        require(sandbox.files().listDirectory("project", 0).isEmpty(), "Zero-depth listing changed");
        remember(sandbox.commands().run("ln -s /etc /workspace/project/link"), ids, 0);
        var entries = sandbox.files().listDirectory("project", 5);
        require(entries.size() == 3 && entries.get(0).getType().equals("symlink"), "Listing followed a link");
        replacements(sandbox, checks);
        searches(sandbox, checks);
        downloads(sandbox, checks);
        directoryChanges(sandbox, ids);
        checks.add("directory-creation-metadata-depth-links-mode-move-and-recursive-deletion");
    }

    private static void replacements(Sandbox sandbox, List<String> checks) {
        byte[] data = {(byte) 0xff, 'a', 'b', 'c', 'a', 'b', 'c', 0};
        sandbox.files()
                .writeFile(WriteEntry.builder()
                        .path("project/replace.bin")
                        .data(data)
                        .mode(640)
                        .build());
        var result = sandbox.files()
                .replaceContentsDetailed(List.of(ContentReplaceEntry.builder()
                        .path("project/replace.bin")
                        .oldContent("abc")
                        .newContent("x")
                        .build()));
        require(
                result.size() == 1
                        && result.get(0).getPath().equals("project/replace.bin")
                        && result.get(0).getReplacedCount() == 2,
                "Replacement count changed");
        require(
                Arrays.equals(
                        sandbox.files().readByteArray("project/replace.bin"), new byte[] {(byte) 0xff, 'x', 'x', 0}),
                "Literal replacement changed unrelated bytes");
        result = sandbox.files()
                .replaceContentsDetailed(List.of(ContentReplaceEntry.builder()
                        .path("project/replace.bin")
                        .oldContent("missing")
                        .newContent("unused")
                        .build()));
        require(result.get(0).getReplacedCount() == 0, "Unmatched replacement changed its count");
        sandbox.files()
                .replaceContents(List.of(ContentReplaceEntry.builder()
                        .path("project/replace.bin")
                        .oldContent("x")
                        .newContent("X")
                        .build()));
        require(
                Arrays.equals(
                        sandbox.files().readByteArray("project/replace.bin"), new byte[] {(byte) 0xff, 'X', 'X', 0}),
                "Non-verbose replacement changed bytes");
        require(
                sandbox.files()
                                .readFileInfo(List.of("project/replace.bin"))
                                .get("project/replace.bin")
                                .getMode()
                        == 640,
                "Replacement changed permissions");
        checks.add("streamed-literal-replacement-counts-binary-preservation-and-mode");
    }

    private static void searches(Sandbox sandbox, List<String> checks) {
        sandbox.files()
                .createDirectories(
                        List.of(WriteEntry.builder().path("project/src/nested").build()));
        for (String path : List.of("project/src/中.rs", "project/src/a.py", "project/src/nested/deep.rs")) {
            sandbox.files().writeFile(path, "source");
        }
        var matches = sandbox.files()
                .search(SearchEntry.builder().path("project").pattern("*.rs").build());
        require(
                matches.stream()
                        .map(item -> item.getPath())
                        .toList()
                        .equals(List.of("/workspace/project/src/nested/deep.rs", "/workspace/project/src/中.rs")),
                "Recursive search changed");
        matches = sandbox.files()
                .search(SearchEntry.builder().path("project").pattern("?.rs").build());
        require(matches.size() == 1 && matches.get(0).getPath().endsWith("/中.rs"), "Glob split a Unicode character");
        matches = sandbox.files()
                .search(SearchEntry.builder()
                        .path("project")
                        .pattern("{*.rs,*.py}")
                        .build());
        require(matches.size() == 3, "Glob alternatives changed");
        require(
                sandbox.files()
                        .search(SearchEntry.builder()
                                .path("project")
                                .pattern("src/*.rs")
                                .build())
                        .isEmpty(),
                "Search matched a relative path instead of a basename");
        matches = sandbox.files()
                .search(SearchEntry.builder()
                        .path("project")
                        .pattern("!(main.txt)")
                        .build());
        require(
                matches.size() == 5
                        && matches.stream().noneMatch(item -> item.getPath().endsWith("/main.txt")),
                "Whole-name negation changed");
        require(matches.stream().anyMatch(item -> "symlink".equals(item.getType())), "Search followed or hid a link");
        checks.add("recursive-basename-globs-unicode-alternatives-and-link-boundaries");
    }

    private static void downloads(Sandbox sandbox, List<String> checks) {
        byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        sandbox.files().writeFile("project/range.bin", data);
        require(
                Arrays.equals(
                        sandbox.files().readByteArray("project/range.bin", "bytes=3-7"),
                        Arrays.copyOfRange(data, 3, 8)),
                "Byte range changed");
        require(
                Arrays.equals(
                        sandbox.files().readByteArray("project/range.bin", "bytes=12-"),
                        Arrays.copyOfRange(data, 12, 16)),
                "Open range changed");
        require(
                Arrays.equals(
                        sandbox.files().readByteArray("project/range.bin", "bytes=-4"),
                        Arrays.copyOfRange(data, 12, 16)),
                "Suffix range changed");
        sandbox.files().writeFile("project/lines.log", "one\r\n\r\nthree\r\nfour\rlast\n");
        require(
                sandbox.files()
                        .readFile("project/lines.log", "UTF-8", null, 2, 2)
                        .equals("\nthree"),
                "Line selection changed");
        require(
                sandbox.files()
                        .readFile("project/lines.log", "UTF-8", null, null, 2)
                        .equals("one\n"),
                "Line limit changed");
        require(
                sandbox.files()
                        .readFile("project/lines.log", "UTF-8", null, 4, null)
                        .equals("four\rlast"),
                "Line suffix changed");
        require(
                sandbox.files()
                        .readFile("project/lines.log", "UTF-8", null, 99, null)
                        .isEmpty(),
                "Line EOF changed");
        checks.add("byte-range-prefix-suffix-and-normalized-line-selection");
    }

    private static void directoryChanges(Sandbox sandbox, List<String> ids) {
        sandbox.files()
                .setPermissions(List.of(SetPermissionEntry.builder()
                        .path("project/src/main.txt")
                        .mode(640)
                        .build()));
        sandbox.files()
                .moveFiles(List.of(MoveEntry.builder()
                        .src("project/src")
                        .dest("project/renamed")
                        .build()));
        sandbox.files()
                .moveFiles(List.of(MoveEntry.builder()
                        .src("project/renamed/main.txt")
                        .dest("project/renamed/run.txt")
                        .build()));
        Execution checked = sandbox.commands()
                .run(RunCommandRequest.builder()
                        .argv(List.of(
                                "python3",
                                "-c",
                                "from pathlib import Path; import os,stat; p=Path('project/renamed/run.txt'); "
                                        + "assert p.read_text()=='original'; assert stat.S_IMODE(p.stat().st_mode)==0o640; "
                                        + "assert p.stat().st_uid==os.getuid(); print('metadata verified')"))
                        .build());
        remember(checked, ids, 0);
        require(output(checked).equals("metadata verified\n"), "Sandbox-side metadata checks failed");
        sandbox.files().deleteFiles(List.of("project/link"));
        sandbox.files().deleteDirectories(List.of("project"));
        remember(sandbox.commands().run("test ! -e /workspace/project && test -f /workspace/text"), ids, 0);
    }

    static void remember(Execution execution, List<String> ids, int code) {
        require(execution.getComplete() != null, "Command completion was not observed");
        require(Integer.valueOf(code).equals(execution.getExitCode()), "Command exit code changed");
        ids.add(execution.getId());
    }

    static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
