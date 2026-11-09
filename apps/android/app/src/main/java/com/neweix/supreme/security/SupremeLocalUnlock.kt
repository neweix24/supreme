package com.neweix.supreme.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Per-use, device-local strong-biometric gate.
 *
 * Android Keystore AES/GCM is used because a per-use authenticated HMAC key
 * may reject Mac.init() before the biometric prompt can authorize the operation
 * on some Android Keystore providers. A Cipher can be initialized before the
 * prompt; doFinal() is the protected operation and is only permitted afterward.
 *
 * This is only a local privacy lock. Server-side AAL2 and device-bound app
 * session checks remain mandatory for protected operations.
 */
internal object SupremeLocalUnlock {
    private const val KEY_ALIAS = "com.neweix.supreme.local_unlock.aes.v2"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val CHALLENGE_BYTES = 32

    data class PreparedOperation(
        val cipher: Cipher,
        val challenge: ByteArray,
    )

    fun allowedAuthenticators(): Int =
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG

    @Synchronized
    fun prepareCipher(): PreparedOperation {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: createKey()

        val cipher = try {
            createCipher(key)
        } catch (_: KeyPermanentlyInvalidatedException) {
            keyStore.deleteEntry(KEY_ALIAS)
            createCipher(createKey())
        }

        val challenge = ByteArray(CHALLENGE_BYTES)
        SecureRandom().nextBytes(challenge)
        return PreparedOperation(cipher, challenge)
    }

    private fun createKey(): SecretKey {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
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

    private fun createCipher(key: SecretKey): Cipher =
        Cipher.getInstance(CIPHER_TRANSFORMATION).apply {
            // Per-use authorization is enforced by Android Keystore when
            // doFinal() executes after BiometricPrompt succeeds.
            init(Cipher.ENCRYPT_MODE, key)
        }
}
