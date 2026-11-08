plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}


apply(from = "logo-guard.gradle.kts")
val releaseKeystorePath = providers.environmentVariable("SUPREME_RELEASE_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("SUPREME_RELEASE_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("SUPREME_RELEASE_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("SUPREME_RELEASE_KEY_PASSWORD").orNull
val configuredVersionCode = providers.environmentVariable("SUPREME_VERSION_CODE").orNull
val appVersionCode = configuredVersionCode?.let {
    it.toIntOrNull() ?: error("SUPREME_VERSION_CODE must be a positive integer.")
} ?: 3
require(appVersionCode > 0) { "SUPREME_VERSION_CODE must be a positive integer." }
val appVersionName = providers.environmentVariable("SUPREME_VERSION_NAME").orNull
    ?.takeIf { it.isNotBlank() } ?: "1.1.0"

android {
    namespace = "com.neweix.supreme"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.neweix.supreme"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName

        // A Supabase publishable key is public-client configuration only.
        // Service-role keys and provider credentials must never be embedded here.
        buildConfigField("String", "SUPABASE_URL", "\"https://grhybvlhdnzlopwbaqun.supabase.co\"")
        buildConfigField("String", "SUPABASE_PUBLISHABLE_KEY", "\"sb_publishable_878YOLa9axxFwNy_ly1MNA_XKJFUDbv\"")
        buildConfigField("String", "SUPREME_TURNSTILE_SITE_KEY", "\"0x4AAAAAAFuD44weVKxUV7gX\"")
    }

    signingConfigs {
        create("release") {
            if (!releaseKeystorePath.isNullOrBlank()) {
                storeFile = file(releaseKeystorePath)
            }
            storePassword = releaseStorePassword
            keyAlias = releaseKeyAlias
            keyPassword = releaseKeyPassword
        }
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

val validateSupremeReleaseSigning = tasks.register("validateSupremeReleaseSigning") {
    doLast {
        val required = mapOf(
            "SUPREME_RELEASE_KEYSTORE_PATH" to releaseKeystorePath,
            "SUPREME_RELEASE_STORE_PASSWORD" to releaseStorePassword,
            "SUPREME_RELEASE_KEY_ALIAS" to releaseKeyAlias,
            "SUPREME_RELEASE_KEY_PASSWORD" to releaseKeyPassword,
        )
        val missing = required.filterValues { it.isNullOrBlank() }.keys
        check(missing.isEmpty()) {
            "Production release signing is not configured. Missing: ${missing.joinToString()}"
        }
        check(file(releaseKeystorePath!!).isFile) {
            "The configured Supreme production keystore file does not exist."
        }
    }
}

tasks.configureEach {
    if (name == "assembleRelease" || name == "bundleRelease" || name == "packageRelease") {
        dependsOn(validateSupremeReleaseSigning)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.webkit:webkit:1.12.1")
}
