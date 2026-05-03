package com.trusttunnel.android

import android.app.Application

/**
 * Custom Application entry point.
 *
 * logback-android 2.x registers its own ContentProvider in the merged
 * AndroidManifest and initialises itself (including DATA_DIR resolution)
 * before Application.onCreate() is called.  No explicit setup is required.
 */
class TrustTunnelApp : Application()
