package com.radixdlt.connect.iroh

import android.content.Context

/**
 * Android-specific setup of Radix Connect over iroh.
 */
object RadixConnectIrohAndroid {

    init {
        System.loadLibrary("radix_connect_iroh_uniffi")
    }

    /**
     * Lets iroh resolve the relay with the device's DNS servers. Call it once per process,
     * before the first [IrohSession]; later calls are ignored. Without it iroh falls back
     * to public DNS resolvers.
     *
     * Only the application context is retained, never [context] itself.
     */
    fun installAndroidContext(context: Context) {
        nativeInstall(context.applicationContext)
    }

    @JvmStatic
    private external fun nativeInstall(applicationContext: Context)
}
