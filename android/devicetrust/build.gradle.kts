plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

group = "com.devicetrust"
version = providers.gradleProperty("cyclone.version").get()

android {
    namespace = "com.devicetrust.client"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        // Android 8+: hardware attestation with attested device IDs. StrongBox (28)
        // and device-property attestation (31) are used when available.
        minSdk = 26
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        consumerProguardFiles("consumer-rules.pro")
    }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

// Run 18: the consumable AAR. Published to a local file repository only; where it is
// distributed from (and under which licence) is an owner decision, see docs/DEPENDENCY_LICENSES.md.
publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.devicetrust"
            artifactId = "devicetrust"
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("Cyclone Scan Device Trust SDK")
                description.set("Collects hardware-attested device evidence for a customer-operated verification service.")
            }
        }
    }
    repositories {
        maven {
            name = "localBeta"
            url = uri(layout.buildDirectory.dir("repo"))
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.10.2")
    implementation("com.google.android.play:integrity:1.6.0")
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    // Real org.json for JVM unit tests (Android's copy is stubbed off-device).
    testImplementation("org.json:json:20240303")
}
