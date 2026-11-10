package com.neweix.supreme.auth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class PendingSupremeMfaSession(
    val accessToken: String,
    val refreshToken: String,
    val userId: String,
    val sessionId: String,
    val expiresAtEpochSeconds: Long,
)

/**
 * Holds the short-lived access and refresh tokens issued after successful TOTP MFA,
 * while hardware device registration is pending. The token is encrypted with
 * a non-exportable Android Keystore key and expires after ten minutes.
 */
internal class SupremePendingMfaStore(context: Context) {
    private val atomicFile = AtomicFile(File(context.noBackupFilesDir, "supreme-pending-mfa.bin"))

    @Synchronized
    fun save(accessToken: String, refreshToken: String, userId: String, sessionId: String) {
        require(accessToken.length in 40..16384 && refreshToken.isNotBlank() && refreshToken.length <= 8192 && refreshToken != "null")
        require(UUID_PATTERN.matches(userId) && UUID_PATTERN.matches(sessionId))
        val expiresAt = System.currentTimeMillis() / 1000L + PENDING_TTL_SECONDS
        val plain = JSONObject()
            .put("access_token", accessToken)
            .put("refresh_token", refreshToken)
            .put("user_id", userId)
            .put("session_id", sessionId)
            .put("expires_at", expiresAt)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(plain)
        val iv = cipher.iv
        require(iv.size == 12) { "Unexpected Android Keystore IV length." }
        val output = ByteArray(1 + iv.size + encrypted.size)
        output[0] = iv.size.toByte()
        System.arraycopy(iv, 0, output, 1, iv.size)
        System.arraycopy(encrypted, 0, output, 1 + iv.size, encrypted.size)

        val stream = atomicFile.startWrite()
        try {
            stream.write(output)
            atomicFile.finishWrite(stream)
        } catch (error: Throwable) {
            atomicFile.failWrite(stream)
            throw error
        }
    }

    @Synchronized
    fun read(): PendingSupremeMfaSession? {
        val bytes = try {
            atomicFile.openRead().use { it.readBytes() }
        } catch (_: FileNotFoundException) {
            return null
        } catch (_: Exception) {
            atomicFile.delete()
            return null
        }
        if (bytes.size < 1 + 12 + 16) {
            atomicFile.delete()
            return null
        }
        val ivLength = bytes[0].toInt() and 0xff
        if (ivLength != 12 || bytes.size <= 1 + ivLength + 16) {
            atomicFile.delete()
            return null
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                GCMParameterSpec(128, bytes.copyOfRange(1, 1 + ivLength)),
            )
            val json = JSONObject(
                String(cipher.doFinal(bytes.copyOfRange(1 + ivLength, bytes.size)), Charsets.UTF_8),
            )
            val access = json.optString("access_token")
            val refresh = json.optString("refresh_token")
            val userId = json.optString("user_id")
            val sessionId = json.optString("session_id")
            val expiresAt = json.optLong("expires_at", 0L)
            val now = System.currentTimeMillis() / 1000L
            if (access.length !in 40..16384 || refresh.isBlank() || refresh.length > 8192 || refresh == "null" ||
                !UUID_PATTERN.matches(userId) || !UUID_PATTERN.matches(sessionId) ||
                expiresAt <= now || expiresAt > now + PENDING_TTL_SECONDS
            ) {
                atomicFile.delete()
                null
            } else {
                PendingSupremeMfaSession(access, refresh, userId, sessionId, expiresAt)
            }
        } catch (_: Exception) {
            atomicFile.delete()
            null
        }
    }

    @Synchronized
    fun clear() {
        atomicFile.delete()
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
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
        const val KEY_ALIAS = "com.neweix.supreme.pending-mfa.aes.v1"
        const val PENDING_TTL_SECONDS = 10 * 60L
        val UUID_PATTERN = Regex(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            RegexOption.IGNORE_CASE,
        )
    }
}
