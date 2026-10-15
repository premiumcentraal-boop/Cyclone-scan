plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Must match the SDK version published by ../devicetrust (android/gradle.properties).
val sdkVersion = "0.9.0-beta.1"

android {
    namespace = "com.example.devicetrustsample"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.devicetrustsample"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        // Your verification service, reached through your own authenticated backend.
        buildConfigField("String", "TRUST_API", "\"https://api.example.com/device-trust\"")
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("com.devicetrust:devicetrust:$sdkVersion")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
}
