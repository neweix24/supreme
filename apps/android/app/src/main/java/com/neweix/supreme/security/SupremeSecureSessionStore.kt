package com.neweix.supreme.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted at-rest storage for the short-lived Supabase session pair.
 * The refresh token is never written to plaintext preferences or logs.
 */
internal class SupremeSecureSessionStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun save(session: SupremeAuthClient.AuthSession) {
        val payload = JSONObject()
            .put("access_token", session.accessToken)
            .put("refresh_token", session.refreshToken)
            .put("expires_in", session.expiresIn)
            .put("token_type", session.tokenType)
            .put("user_id", session.userId)
            .put("aal", session.aal)
            .toString()
        val encrypted = encrypt(payload.toByteArray(Charsets.UTF_8))
        check(preferences.edit().putString(SESSION_KEY, Base64.encodeToString(encrypted, Base64.NO_WRAP)).commit()) {
            "Could not persist the encrypted Supreme session."
        }
    }

    fun load(): SupremeAuthClient.AuthSession? {
        val encoded = preferences.getString(SESSION_KEY, null) ?: return null
        return try {
            val encrypted = Base64.decode(encoded, Base64.NO_WRAP)
            val json = JSONObject(String(decrypt(encrypted), Charsets.UTF_8))
            SupremeAuthClient.AuthSession(
                accessToken = json.getString("access_token"),
                refreshToken = json.getString("refresh_token"),
                expiresIn = json.optLong("expires_in"),
                tokenType = json.optString("token_type", "bearer"),
                userId = json.getString("user_id"),
                aal = json.optString("aal"),
            )
        } catch (_: Exception) {
            clear()
            null
        }
    }

    fun clear() {
        preferences.edit().remove(SESSION_KEY).commit()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plain)
        return ByteBuffer.allocate(1 + iv.size + encrypted.size)
            .put(iv.size.toByte()).put(iv).put(encrypted).array()
    }

    private fun decrypt(value: ByteArray): ByteArray {
        require(value.size > 13) { "Encrypted Supreme session is truncated." }
        val buffer = ByteBuffer.wrap(value)
        val ivLength = buffer.get().toInt() and 0xff
        require(ivLength == 12 && buffer.remaining() > ivLength) { "Invalid encrypted session IV." }
        val iv = ByteArray(ivLength).also { buffer.get(it) }
        val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun getOrCreateKey(): SecretKey {
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    companion object {
        private const val PREFERENCES = "supreme_secure_session"
        private const val SESSION_KEY = "encrypted_session_v1"
        private const val KEY_ALIAS = "com.neweix.supreme.session.aes.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
