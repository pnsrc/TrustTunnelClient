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
// platform/android/lib contains the JNI bridge (VpnClient, VpnState, …) and
// the CMake build that links trusttunnel_android.so.
//
// Prerequisites for the native build:
//   1. NDK 28.1.13356709 installed via SDK Manager
//   2. Conan 2 + project dependencies bootstrapped:
//        python scripts/bootstrap_conan_deps.py android
//
// If the native .so has not been compiled yet the Kotlin API still compiles;
// the VPN service catches UnsatisfiedLinkError at runtime and falls back to a
// no-op tunnel so the app remains launchable.
include(":trusttunnel-lib")
project(":trusttunnel-lib").projectDir = file("../../platform/android/lib")
