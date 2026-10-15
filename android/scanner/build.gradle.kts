plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.devicetrust.scanner"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.devicetrust.scanner"
        minSdk = 26
        targetSdk = 35
        versionCode = providers.gradleProperty("cyclone.versionCode").get().toInt()
        versionName = providers.gradleProperty("cyclone.version").get()
    }

    // Run 18: the approved signing identity comes only from the secret store (CI secrets
    // or the release operator's environment). This build never generates a key. Without
    // all four values the release APK is a test build signed with the local debug key;
    // -Pcyclone.requireReleaseSigning=true turns that into a build failure.
    val releaseStore = System.getenv("CYCLONE_RELEASE_STORE_FILE")?.takeIf { it.isNotBlank() }
    val releaseSigning = releaseStore != null && listOf(
        "CYCLONE_RELEASE_STORE_PASSWORD", "CYCLONE_RELEASE_KEY_ALIAS", "CYCLONE_RELEASE_KEY_PASSWORD",
    ).all { !System.getenv(it).isNullOrEmpty() }
    if (!releaseSigning && providers.gradleProperty("cyclone.requireReleaseSigning").orNull == "true") {
        throw GradleException("release signing required but CYCLONE_RELEASE_* secrets are not set")
    }
    signingConfigs {
        if (releaseSigning) {
            create("release") {
                storeFile = file(releaseStore!!)
                storePassword = System.getenv("CYCLONE_RELEASE_STORE_PASSWORD")
                keyAlias = System.getenv("CYCLONE_RELEASE_KEY_ALIAS")
                keyPassword = System.getenv("CYCLONE_RELEASE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Optimised and NOT debuggable (a debuggable app would flag itself).
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName(if (releaseSigning) "release" else "debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(project(":devicetrust"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
