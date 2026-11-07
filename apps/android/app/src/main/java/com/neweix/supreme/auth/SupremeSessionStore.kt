package com.neweix.supreme.auth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores only the rotating Supabase refresh token. The access token stays in
 * memory and is short-lived. The file is encrypted with a non-exportable
 * Android Keystore AES-256-GCM key.
 */
internal class SupremeSessionStore(context: Context) {
    private val file = File(context.noBackupFilesDir, "supreme-session.bin")

    @Synchronized
    fun saveRefreshToken(token: String) {
        require(token.isNotBlank() && token.length <= 8192 && token != "null") { "Invalid Supreme refresh token." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        require(iv.size == 12) { "Unexpected Android Keystore IV length." }
        val output = ByteArray(1 + iv.size + encrypted.size)
        output[0] = iv.size.toByte()
        System.arraycopy(iv, 0, output, 1, iv.size)
        System.arraycopy(encrypted, 0, output, 1 + iv.size, encrypted.size)
        file.writeBytes(output)
    }

    @Synchronized
    fun readRefreshToken(): String? {
        if (!file.exists()) return null
        return try {
            val input = file.readBytes()
            if (input.size < 1 + 12 + 16) return null
            val ivLength = input[0].toInt() and 0xff
            if (ivLength != 12 || input.size <= 1 + ivLength + 16) return null
            val iv = input.copyOfRange(1, 1 + ivLength)
            val ciphertext = input.copyOfRange(1 + ivLength, input.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8).takeIf { it.isNotBlank() && it.length <= 8192 && it != "null" }
        } catch (_: Exception) {
            clear()
            null
        }
    }

    @Synchronized
    fun clear() {
        if (file.exists()) file.delete()
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore",
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "com.neweix.supreme.session.aes.v1"
    }
}
