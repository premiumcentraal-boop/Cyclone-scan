import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The SDK version published by ../devicetrust, read from android/gradle.properties so the
// sample always builds against the AAR of the same checkout. A customer app pins a version.
val sdkVersion: String = Properties().apply {
    rootDir.resolve("../gradle.properties").inputStream().use { load(it) }
}.getProperty("cyclone.version")

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
