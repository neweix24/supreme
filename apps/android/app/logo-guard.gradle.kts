// Supreme logo guard.
import java.security.MessageDigest

val supremeLogoFiles = listOf(
    "src/main/assets/supreme-logo.svg",
    "src/main/res/drawable/supreme_logo.xml",
    "src/main/res/drawable/supreme_icon_foreground.xml",
    "src/main/res/drawable/supreme_icon_monochrome.xml",
    "src/main/res/drawable/supreme_splash_icon.xml",
    "src/main/res/mipmap-anydpi-v26/ic_launcher.xml",
    "src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml",
)
val supremeLogoLock = file("logo.lock")

fun supremeLogoHash(f: File): String {
    val text = f.readText(Charsets.UTF_8).replace("\r\n", "\n")
    return MessageDigest.getInstance("SHA-256")
        .digest(text.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}

fun supremeLogoLockContent(): String =
    supremeLogoFiles.joinToString("\n") { "${supremeLogoHash(file(it))}  $it" } + "\n"

val verifySupremeLogo = tasks.register("verifySupremeLogo") {
    group = "verification"
    description = "Checks that Supreme logo resources are present, vector-based and unchanged."
    doLast {
        val problems = mutableListOf<String>()
        val missing = supremeLogoFiles.filterNot { file(it).isFile }
        missing.forEach { problems += "Missing logo file: $it" }

        file("src/main/res").walkTopDown()
            .filter { it.isFile && it.nameWithoutExtension.startsWith("ic_launcher") &&
                it.extension.lowercase() in setOf("png", "jpg", "jpeg", "webp") }
            .forEach { problems += "Raster launcher icon is not allowed: ${it.relativeTo(projectDir)}" }

        for (name in listOf("ic_launcher", "ic_launcher_round")) {
            val xml = file("src/main/res/mipmap-anydpi-v26/$name.xml")
            if (xml.isFile && !xml.readText().contains("<monochrome")) {
                problems += "$name.xml has no <monochrome> layer."
            }
        }

        if (missing.isEmpty()) {
            if (!supremeLogoLock.isFile) {
                problems += "logo.lock is missing. Run: gradle :app:updateSupremeLogoLock"
            } else if (supremeLogoLock.readText().replace("\r\n", "\n") != supremeLogoLockContent()) {
                problems += "Logo files changed but logo.lock was not updated. Run: gradle :app:updateSupremeLogoLock"
            }
        }
        check(problems.isEmpty()) { "Supreme logo check failed:\n - " + problems.joinToString("\n - ") }
    }
}

tasks.register("updateSupremeLogoLock") {
    group = "verification"
    description = "Records the current logo files as the approved logo."
    doLast {
        supremeLogoLock.writeText(supremeLogoLockContent())
        println("logo.lock updated.")
    }
}

tasks.configureEach {
    if (name == "preBuild") dependsOn(verifySupremeLogo)
}
