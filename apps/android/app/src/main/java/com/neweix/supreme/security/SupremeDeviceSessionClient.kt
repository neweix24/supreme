package com.neweix.supreme.security

import android.os.Looper
import com.neweix.supreme.BuildConfig
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/** Server-authoritative Supreme device-session status and self-revocation. */
internal class SupremeDeviceSessionClient {
    data class Status(
        val authenticated: Boolean,
        val deviceSessionActive: Boolean,
        val sessionId: String?,
        val deviceId: String?,
        val securityLevel: String?,
        val expiresAt: String?,
    )

    fun getStatus(accessToken: String): Status {
        assertWorkerThread()
        val (status, body) = request("GET", accessToken)
        if (status !in 200..299) throw IllegalStateException("Supreme device session could not be verified.")
        val json = JSONObject(body)
        val active = json.optBoolean("device_session_active", false)
        val session = json.optJSONObject("session")
        return Status(
            authenticated = json.optBoolean("authenticated", false),
            deviceSessionActive = active,
            sessionId = session?.optString("session_id")?.takeIf(String::isNotBlank),
            deviceId = session?.optString("device_id")?.takeIf(String::isNotBlank),
            securityLevel = session?.optString("security_level")?.takeIf(String::isNotBlank),
            expiresAt = session?.optString("expires_at")?.takeIf(String::isNotBlank),
        )
    }

    fun revokeCurrent(accessToken: String) {
        assertWorkerThread()
        val (status, _) = request("DELETE", accessToken)
        if (status !in 200..299 && status != 409) {
            throw IllegalStateException("Supreme device session revocation could not be confirmed.")
        }
    }

    private fun request(method: String, accessToken: String): Pair<Int, String> {
        require(accessToken.isNotBlank()) { "Supreme access token is required." }
        val origin = BuildConfig.SUPABASE_URL.trimEnd('/')
        val key = BuildConfig.SUPABASE_ANON_KEY
        require(origin.startsWith("https://") && key.isNotBlank()) {
            "Supreme session API is not configured in this app build."
        }
        val url = URL("$origin/functions/v1/supreme-session-api")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            useCaches = false
            doInput = true
            setRequestProperty("apikey", key)
            setRequestProperty("Authorization", "Bearer $accessToken")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
        }
        try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                ?: return status to ""
            val body = stream.use {
                val bytes = it.readNBytes(MAX_RESPONSE_BYTES + 1)
                require(bytes.size <= MAX_RESPONSE_BYTES) { "Supreme session response was too large." }
                String(bytes, StandardCharsets.UTF_8)
            }
            return status to body
        } finally {
            connection.disconnect()
        }
    }

    private fun assertWorkerThread() {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Supreme session network operations must run off the Android UI thread."
        }
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 16 * 1024
    }
}
