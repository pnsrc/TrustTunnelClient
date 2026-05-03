pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "trusttunnel-android"
include(":app")

// ── TrustTunnel native library ────────────────────────────────────────────────
// The VpnClient / VpnState / NativeLogger Kotlin sources are vendored directly
// under app/src/main/kotlin/com/adguard/trusttunnel/ so the JNI function names
// (Java_com_adguard_trusttunnel_VpnClient_*) match what trusttunnel_android.so
// exports — no separate Gradle module required.
//
// To compile the native .so, run:
//   python scripts/bootstrap_conan_deps.py android
// and build platform/android with NDK 28.1.13356709.
