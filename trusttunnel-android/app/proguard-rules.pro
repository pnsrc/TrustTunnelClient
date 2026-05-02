# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Keep TrustTunnel classes
-keep class com.trusttunnel.android.** { *; }
-keep class com.trusttunnel.android.data.** { *; }

# Keep ML Kit classes
-keep class com.google.mlkit.** { *; }

# Keep Camera X classes
-keep class androidx.camera.** { *; }

# Keep Kotlin classes
-keepclasseswithmembernames class * {
    native <methods>;
}

# Add any other ProGuard rules here
