plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.neweix.supreme"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.neweix.supreme"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.1.0"

        // A Supabase publishable key is public-client configuration only.
        // Service-role keys and provider credentials must never be embedded here.
        buildConfigField("String", "SUPABASE_URL", "\"https://grhybvlhdnzlopwbaqun.supabase.co\"")
        buildConfigField("String", "SUPABASE_PUBLISHABLE_KEY", "\"sb_publishable_878YOLa9axxFwNy_ly1MNA_XKJFUDbv\"")
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.biometric:biometric:1.1.0")
}
