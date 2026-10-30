plugins {
    application
    checkstyle
    id("com.diffplug.spotless") version "8.10.1"
}

repositories { mavenCentral() }
java { toolchain { languageVersion = JavaLanguageVersion.of(26) } }
dependencies {
    implementation("com.alibaba.opensandbox:sandbox:1.1.0")
    implementation("tools.jackson.core:jackson-databind:3.1.5")
}
dependencyLocking { lockAllConfigurations() }
application { mainClass = "example.sandcrab.SdkConformance" }
tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }
spotless {
    java {
        palantirJavaFormat("2.97.0")
        importOrder("\\#", "")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
}
checkstyle {
    toolVersion = "14.1.0"
    maxWarnings = 0
    configDirectory = file("../../../config/checkstyle")
    configFile = file("../../../config/checkstyle/checkstyle.xml")
}
