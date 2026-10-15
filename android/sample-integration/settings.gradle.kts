// Run 18: a separate Gradle build that consumes the SDK only as a published Maven artifact,
// exactly as a customer app would. Build it after publishing the AAR:
//   cd android
//   ./gradlew :devicetrust:publishReleasePublicationToLocalBetaRepository
//   ./gradlew -p sample-integration :app:assembleDebug
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version "8.7.3"
        id("org.jetbrains.kotlin.android") version "2.0.21"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // The locally published beta AAR; replace with your distribution repository.
        maven { url = uri("../devicetrust/build/repo") }
        google()
        mavenCentral()
    }
}

rootProject.name = "DeviceTrustSampleIntegration"
include(":app")
