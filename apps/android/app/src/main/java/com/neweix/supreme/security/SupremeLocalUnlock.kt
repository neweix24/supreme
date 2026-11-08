package com.neweix.supreme.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Per-use, device-local biometric/credential gate for revealing the cached
 * Supreme screen. The Android prompt authorizes a non-exportable Keystore HMAC
 * key; the callback must complete the MAC operation before the UI unlocks.
 *
 * This is only a local privacy lock. Server-side AAL2 and device-bound app
 * session checks remain mandatory for protected operations.
 */
internal object SupremeLocalUnlock {
    private const val KEY_ALIAS = "com.neweix.supreme.local_unlock.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val MAC_ALGORITHM = "HmacSHA256"
    private const val CHALLENGE_BYTES = 32

    fun allowedAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    @Synchronized
    fun prepareMac(): Mac {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: createKey()

        return try {
            createMac(key)
        } catch (_: KeyPermanentlyInvalidatedException) {
            keyStore.deleteEntry(KEY_ALIAS)
            createMac(createKey())
        }
    }

    private fun createKey(): SecretKey {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, allowedAuthenticators())
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun createMac(key: SecretKey): Mac {
        val challenge = ByteArray(CHALLENGE_BYTES)
        SecureRandom().nextBytes(challenge)
        return try {
            Mac.getInstance(MAC_ALGORITHM).apply {
                init(key)
                update(challenge)
            }
        } finally {
            challenge.fill(0)
        }
    }
}
