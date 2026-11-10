package com.neweix.supreme.auth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.time.Instant
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores only the rotating Supabase refresh token. The access token stays in
 * memory and is short-lived. The file is encrypted with a non-exportable
 * Android Keystore AES-256-GCM key and committed atomically.
 */
internal class SupremeSessionStore(context: Context) {
    private val file = File(context.noBackupFilesDir, "supreme-session.bin")
    private val atomicFile = AtomicFile(file)
    private val diagnosticsFile = File(context.noBackupFilesDir, "supreme-diagnostics.log")

    @Synchronized
    fun record(event: String) {
        try {
            val safeEvent = event.replace(Regex("[^A-Za-z0-9_ =:./-]"), "_").take(180)
            val previous = if (diagnosticsFile.exists()) diagnosticsFile.readLines().takeLast(180) else emptyList()
            val lines = (previous + "${Instant.now()} $safeEvent").takeLast(200)
            diagnosticsFile.writeText(lines.joinToString("\n", postfix = "\n"))
        } catch (_: Exception) { /* Diagnostics must never interrupt authentication. */ }
    }

    @Synchronized
    fun exportDiagnostics(): String = try {
        if (diagnosticsFile.exists()) diagnosticsFile.readText().takeLast(24000)
        else "No Supreme diagnostics have been recorded."
    } catch (_: Exception) { "Unable to read Supreme diagnostics." }

    @Synchronized
    fun saveRefreshToken(token: String) {
        record("SESSION_SAVE_BEGIN fileExists=${file.exists()}")
        require(token.isNotBlank() && token.length <= 8192 && token != "null") {
            "Invalid Supreme refresh token."
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
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
            record("SESSION_SAVE_COMMIT fileExists=${file.exists()} fileBytes=${file.length()}")
        } catch (error: Throwable) {
            atomicFile.failWrite(stream)
            record("SESSION_SAVE_FAIL type=${error.javaClass.simpleName}")
            throw error
        }
    }

    @Synchronized
    fun readRefreshToken(): String? {
        val input = try {
            atomicFile.openRead().use { it.readBytes() }
        } catch (_: FileNotFoundException) {
            record("SESSION_READ_NOT_FOUND fileExists=${file.exists()}")
            return null
        } catch (error: Exception) {
            // A transient filesystem or Keystore read failure must never erase the
            // only encrypted refresh credential. Preserve the file and fail closed.
            record("SESSION_READ_FILE_FAIL type=${error.javaClass.simpleName} fileExists=${file.exists()} fileBytes=${file.length()}")
            throw IllegalStateException(
                "The encrypted Supreme session file could not be read. The saved credential was preserved.",
                error,
            )
        }

        record("SESSION_READ_FILE_FOUND fileBytes=${input.size}")
        if (input.size < 1 + 12 + 16) {
            throw IllegalStateException("The encrypted Supreme session file is incomplete. The saved file was preserved.")
        }
        val ivLength = input[0].toInt() and 0xff
        if (ivLength != 12 || input.size <= 1 + ivLength + 16) {
            throw IllegalStateException("The encrypted Supreme session file has an invalid format. The saved file was preserved.")
        }

        return try {
            val iv = input.copyOfRange(1, 1 + ivLength)
            val ciphertext = input.copyOfRange(1 + ivLength, input.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getExistingKey(), GCMParameterSpec(128, iv))
            val token = String(cipher.doFinal(ciphertext), Charsets.UTF_8)
            require(token.isNotBlank() && token.length <= 8192 && token != "null") {
                "The decrypted Supreme session credential is invalid."
            }
            record("SESSION_READ_DECRYPT_OK")
            token
        } catch (error: Exception) {
            record("SESSION_READ_DECRYPT_FAIL type=${error.javaClass.simpleName}")
            // Do not convert Keystore invalidation, temporary unavailability, or
            // authentication/decryption errors into "no session". That used to
            // delete the credential and send the user to SIGN IN without a cause.
            throw IllegalStateException(
                "The saved Supreme session could not be decrypted. The encrypted credential was preserved.",
                error,
            )
        }
    }

    @Synchronized
    fun clear(reason: String) {
        record("SESSION_CLEAR_BEGIN reason=$reason fileExists=${file.exists()} fileBytes=${file.length()}")
        atomicFile.delete()
        record("SESSION_CLEAR_DONE reason=$reason fileExists=${file.exists()}")
    }

    private fun getExistingKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return store.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("The Android Keystore session key is missing. The encrypted session was preserved.")
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
