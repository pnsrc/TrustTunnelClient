plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization") version "2.1.20"
}

android {
    namespace = "com.trusttunnel.android"
    compileSdk = 35
    // Must match the NDK used to build platform/android/lib
    ndkVersion = "28.1.13356709"

    defaultConfig {
        applicationId = "com.trusttunnel.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // ── Native core ──────────────────────────────────────────────────────
        // Build libtrusttunnel_android.so from the shared platform C++ layer.
        // The CMakeLists.txt at platform/android/lib/src/main/cpp bootstraps
        // Conan and links against the full VPN core, so conan must be in PATH
        // before Gradle invokes CMake.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                targets += "trusttunnel_android"
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
            }
        }
    }

    externalNativeBuild {
        cmake {
            // Two directories up from app/ lands at the repo root; then into
            // platform/android/lib/src/main/cpp/CMakeLists.txt.
            path = file("../../platform/android/lib/src/main/cpp/CMakeLists.txt")
            version = "3.24+"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
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
    // Android & Jetpack
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Camera & ML Kit (for QR code scanning)
    implementation("androidx.camera:camera-core:1.3.0")
    implementation("androidx.camera:camera-camera2:1.3.0")
    implementation("androidx.camera:camera-lifecycle:1.3.0")
    implementation("androidx.camera:camera-view:1.3.0")
    implementation("com.google.mlkit:barcode-scanning:17.2.0")

    // Config parsing
    implementation("com.akuleshov7:ktoml-core:0.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-core:1.7.3")

    // Logging
    implementation("org.slf4j:slf4j-api:1.7.36")
    implementation("com.github.tony19:logback-android:2.0.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
