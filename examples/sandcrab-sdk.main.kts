@file:DependsOn("com.alibaba.opensandbox:sandbox:1.1.0")

import com.alibaba.opensandbox.sandbox.Sandbox
import com.alibaba.opensandbox.sandbox.config.ConnectionConfig
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration

val connection = ConnectionConfig.builder()
    .domain(System.getenv("SANDCRAB_ENDPOINT") ?: "127.0.0.1:9011")
    .protocol("http")
    .apiKey(Files.readString(Path.of(System.getenv("SANDCRAB_TOKEN_FILE") ?: "/etc/sandcrab/token")).trim())
    .build()

Sandbox.builder()
    .image(System.getenv("SANDCRAB_PROFILE") ?: "default")
    .connectionConfig(connection)
    .resource(mapOf("cpu" to "0.25", "memory" to "32Mi"))
    .timeout(Duration.ofSeconds(60))
    .build().use { sandbox ->
        try {
            val execution = sandbox.commands().run("printf '%s' $((6 * 7))")
            check(execution.exitCode == 0) { "The sandbox command failed" }
            println(execution.logs.stdout.joinToString("") { it.text })
        } finally {
            sandbox.kill()
        }
    }
