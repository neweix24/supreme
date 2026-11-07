plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun buildConfigString(value: String): String =
    "\""${value.replace("\\", "\\\\").replace("\"", "\\\"")}\"""

val supremePrivatePath = providers.gradleProperty("supremePrivatePath")
    .orElse(providers.environmentVariable("SUPREME_PRIVATE_PATH"))
    .orNull
    ?: ""

val supabaseUrl = providers.gradleProperty("supabaseUrl")
    .orElse(providers.environmentVariable("SUPABASE_URL"))
    .orNull
    ?: ""

val supabaseAnonKey = providers.gradleProperty("supabaseAnonKey")
    .orElse(providers.environmentVariable("SUPABASE_ANON_KEY"))
    .orNull
    ?: ""

require(Regex("^/control-[A-Fa-f0-9]{48}$").matches(supremePrivatePath)) {
    "Set SUPREME_PRIVATE_PATH (or -PsupremePrivatePath) to the private /control-<48 hex chars> path before building."
}

if (supabaseUrl.isNotBlank()) {
    require(supabaseUrl.startsWith("https://") && !supabaseUrl.endsWith("/")) {
        "SUPABASE_URL must be an HTTPS origin without a trailing slash."
    }
}

android {
    namespace = "com.neweix.supreme"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.neweix.supreme"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.0.2"

        buildConfigField("String", "SITE_ORIGIN", buildConfigString("https://neweix.com"))
        buildConfigField("String", "SUPREME_PRIVATE_PATH", buildConfigString(supremePrivatePath))
        buildConfigField("String", "SUPABASE_URL", buildConfigString(supabaseUrl))
        buildConfigField("String", "SUPABASE_ANON_KEY", buildConfigString(supabaseAnonKey))
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.biometric:biometric:1.1.0")
}
