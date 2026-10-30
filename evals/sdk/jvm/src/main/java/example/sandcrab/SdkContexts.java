package example.sandcrab;

import static example.sandcrab.SdkConformance.output;
import static example.sandcrab.SdkConformance.remember;
import static example.sandcrab.SdkConformance.require;

import com.alibaba.opensandbox.sandbox.Sandbox;
import com.alibaba.opensandbox.sandbox.domain.exceptions.SandboxApiException;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.Execution;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.RunCommandRequest;
import com.alibaba.opensandbox.sandbox.domain.models.execd.filesystem.WriteEntry;
import java.time.Duration;
import java.util.List;

final class SdkContexts {
    private SdkContexts() {}

    static List<String> exercise(Sandbox sandbox, List<String> ids, List<String> checks) {
        sandbox.files()
                .createDirectories(
                        List.of(WriteEntry.builder().path("shell-work/child").build()));
        String first = sandbox.commands().createSession("/workspace/shell-work");
        String second = sandbox.commands().createSession(null);
        remember(
                sandbox.commands()
                        .runInSession(
                                first,
                                "LOCAL=first; marker() { printf function; }; cd child; printf kept > shared",
                                null,
                                (Duration) null),
                ids,
                0);
        Execution result = sandbox.commands()
                .runInSession(first, "printf '%s\\n' \"$LOCAL\" \"$SDK_VALUE\"; pwd; marker", null, (Duration) null);
        remember(result, ids, 0);
        require(
                output(result).equals("first\nbase ' quoted\n/workspace/shell-work/child\nfunction"),
                "Named shell did not preserve its state");
        result = sandbox.commands()
                .runInSession(
                        second, "printf '%s\\n' \"${LOCAL-unset}\"; pwd; cat shell-work/child/shared", null, (Duration)
                                null);
        remember(result, ids, 0);
        require(output(result).equals("unset\n/workspace\nkept"), "Sibling shell state or shared files changed");
        result = sandbox.commands().runInSession(first, "pwd", "/workspace", (Duration) null);
        remember(result, ids, 0);
        require(output(result).equals("/workspace\n"), "Working directory override was ignored");
        result = sandbox.commands().runInSession(first, "pwd", null, (Duration) null);
        remember(result, ids, 0);
        require(output(result).equals("/workspace\n"), "Working directory override did not persist");
        sandbox.commands().deleteSession(first);
        refused(sandbox, first, 404);
        require(
                sandbox.files().readFile("shell-work/child/shared").equals("kept"),
                "Deleting a shell removed its files");
        checks.add("named-shell-state-working-directory-and-delete-preserve-shared-files");
        timeouts(sandbox, second, ids);
        checks.add("named-and-independent-command-timeouts-preserve-the-sandbox");
        try {
            sandbox.commands().createSession("/workspace/missing-context-directory");
            throw new IllegalStateException("Missing working directory created a usable context");
        } catch (SandboxApiException error) {
            require(Integer.valueOf(400).equals(error.getStatusCode()), "Initialization refusal changed");
        }
        return List.of(first, second, sandbox.commands().createSession(null));
    }

    private static void timeouts(Sandbox sandbox, String context, List<String> ids) {
        Execution result = sandbox.commands().runInSession(context, "sleep 30", null, Duration.ofMillis(100));
        ids.add(result.getId());
        require(result.getError() != null, "Named shell timeout was not reported");
        refused(sandbox, context, 409);
        sandbox.commands().deleteSession(context);
        result = sandbox.commands()
                .run(RunCommandRequest.builder()
                        .command("sleep 30")
                        .timeout(Duration.ofMillis(100))
                        .build());
        ids.add(result.getId());
        require(result.getError() != null, "Independent command timeout was not reported");
        result = sandbox.commands().run("test ! -e revived; cat shell-work/child/shared");
        remember(result, ids, 0);
        require(output(result).equals("kept"), "Command timeout removed the shared workspace");
    }

    private static void refused(Sandbox sandbox, String context, int status) {
        try {
            sandbox.commands().runInSession(context, "touch /workspace/revived", null, (Duration) null);
            throw new IllegalStateException("Ended named shell was recreated");
        } catch (SandboxApiException error) {
            require(Integer.valueOf(status).equals(error.getStatusCode()), "Ended shell refusal changed");
        }
    }
}
