package com.neweix.supreme.security

import android.os.Looper
import com.neweix.supreme.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * Native Supabase password + TOTP MFA transport.
 *
 * Password authentication alone never returns an app-authorized state. The
 * caller must complete a verified TOTP factor and then obtain a server-issued
 * Supreme device session before opening the protected workspace.
 */
internal class SupremeAuthClient {
    data class AuthSession(
        val accessToken: String,
        val refreshToken: String,
        val expiresIn: Long,
        val tokenType: String,
        val userId: String,
        val aal: String,
    )

    data class TotpFactor(
        val id: String,
        val friendlyName: String?,
    )

    data class MfaChallenge(
        val factorId: String,
        val challengeId: String,
    )

    sealed interface PasswordResult {
        data class MfaRequired(
            val accessToken: String,
            val refreshToken: String,
            val userId: String,
            val factors: List<TotpFactor>,
        ) : PasswordResult
        data class Complete(val session: AuthSession) : PasswordResult
    }

    fun signInWithPassword(email: String, password: String): PasswordResult {
        assertWorkerThread()
        require(email.isNotBlank() && email.length <= 254) { "Enter a valid Supreme email address." }
        require(password.isNotEmpty() && password.length <= 1024) { "Password is invalid." }

        val response = request(
            method = "POST",
            path = "/auth/v1/token?grant_type=password",
            body = JSONObject().put("email", email.trim()).put("password", password).toString(),
        )
        if (response.first !in 200..299) {
            throw AuthException("Supreme sign-in failed. Check the credentials and try again.")
        }

        val payload = JSONObject(response.second)
        val accessToken = payload.optString("access_token")
        val refreshToken = payload.optString("refresh_token")
        val userId = payload.optJSONObject("user")?.optString("id").orEmpty()
        require(accessToken.isNotBlank() && refreshToken.isNotBlank() && UUID.matches(userId)) {
            "Supabase Auth returned an invalid session."
        }

        val factors = listVerifiedTotpFactors(accessToken)
        if (factors.isEmpty()) {
            throw AuthException("No verified Supreme TOTP factor is enrolled. Access remains locked.")
        }
        return PasswordResult.MfaRequired(accessToken, refreshToken, userId, factors)
    }

    fun createTotpChallenge(accessToken: String, factorId: String): MfaChallenge {
        assertWorkerThread()
        require(UUID.matches(factorId)) { "Invalid MFA factor." }
        val response = request(
            method = "POST",
            path = "/auth/v1/factors/$factorId/challenge",
            accessToken = accessToken,
            body = "{}",
        )
        if (response.first !in 200..299) {
            throw AuthException("Supreme MFA challenge could not be created.")
        }
        val challengeId = JSONObject(response.second).optString("id")
        require(UUID.matches(challengeId)) { "Supreme MFA challenge response was invalid." }
        return MfaChallenge(factorId, challengeId)
    }

    fun verifyTotp(
        accessToken: String,
        refreshToken: String,
        userId: String,
        challenge: MfaChallenge,
        code: String,
    ): AuthSession {
        assertWorkerThread()
        require(code.matches(Regex("^[0-9]{6,8}$"))) { "Enter the current authenticator code." }
        val response = request(
            method = "POST",
            path = "/auth/v1/factors/${challenge.factorId}/verify",
            accessToken = accessToken,
            body = JSONObject()
                .put("challenge_id", challenge.challengeId)
                .put("code", code)
                .toString(),
        )
        if (response.first !in 200..299) {
            throw AuthException("The authenticator code was not accepted.")
        }

        val payload = JSONObject(response.second)
        val newAccessToken = payload.optString("access_token")
        val newRefreshToken = payload.optString("refresh_token")
        require(newAccessToken.isNotBlank() && newRefreshToken.isNotBlank()) {
            "Supreme MFA verification did not return a complete session."
        }
        val aal = readAal(newAccessToken)
        if (aal != "aal2") throw AuthException("Supreme AAL2 assurance was not established.")

        return AuthSession(
            accessToken = newAccessToken,
            refreshToken = newRefreshToken,
            expiresIn = payload.optLong("expires_in", 0),
            tokenType = payload.optString("token_type", "bearer"),
            userId = userId,
            aal = aal,
        )
    }

    fun refresh(session: AuthSession): AuthSession {
        assertWorkerThread()
        val response = request(
            method = "POST",
            path = "/auth/v1/token?grant_type=refresh_token",
            body = JSONObject().put("refresh_token", session.refreshToken).toString(),
        )
        if (response.first !in 200..299) throw AuthException("Supreme session has expired. Sign in again.")
        val payload = JSONObject(response.second)
        val access = payload.optString("access_token")
        val refresh = payload.optString("refresh_token")
        val userId = payload.optJSONObject("user")?.optString("id").orEmpty()
        require(access.isNotBlank() && refresh.isNotBlank() && UUID.matches(userId)) {
            "Supreme session refresh returned an invalid response."
        }
        val aal = readAal(access)
        if (aal != "aal2") throw AuthException("MFA assurance was not preserved during session refresh.")
        return AuthSession(access, refresh, payload.optLong("expires_in", 0),
            payload.optString("token_type", "bearer"), userId, aal)
    }

    fun signOut(accessToken: String) {
        assertWorkerThread()
        val result = request("POST", "/auth/v1/logout", accessToken, "{}")
        if (result.first !in 200..299 && result.first != 401) {
            throw AuthException("Supreme sign-out could not be confirmed.")
        }
    }

    private fun listVerifiedTotpFactors(accessToken: String): List<TotpFactor> {
        val response = request("GET", "/auth/v1/factors", accessToken = accessToken)
        if (response.first !in 200..299) throw AuthException("Supreme MFA configuration could not be loaded.")
        val json = JSONObject(response.second)
        val all = json.optJSONArray("all") ?: json.optJSONArray("totp") ?: JSONArray()
        val result = mutableListOf<TotpFactor>()
        for (index in 0 until all.length()) {
            val factor = all.optJSONObject(index) ?: continue
            if (factor.optString("factor_type", factor.optString("type")) != "totp") continue
            if (factor.optString("status") != "verified") continue
            val id = factor.optString("id")
            if (UUID.matches(id)) result += TotpFactor(id, factor.optString("friendly_name").ifBlank { null })
        }
        return result
    }

    private fun readAal(accessToken: String): String {
        val part = accessToken.split(".").getOrNull(1) ?: return ""
        val normalized = part.replace('-', '+').replace('_', '/')
        val decoded = android.util.Base64.decode(
            normalized.padEnd(((normalized.length + 3) / 4) * 4, '='.code),
            android.util.Base64.DEFAULT,
        )
        return JSONObject(String(decoded, StandardCharsets.UTF_8)).optString("aal")
    }

    private fun request(
        method: String,
        path: String,
        accessToken: String? = null,
        body: String? = null,
    ): Pair<Int, String> {
        val origin = BuildConfig.SUPABASE_URL.trimEnd('/')
        val key = BuildConfig.SUPABASE_ANON_KEY
        require(origin.startsWith("https://") && key.isNotBlank()) {
            "Supreme Auth endpoint is not configured in this app build."
        }
        val url = URL(origin + path)
        require(url.protocol == "https" && url.host.isNotBlank() && url.userInfo == null) {
            "Supreme Auth endpoint is invalid."
        }
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            useCaches = false
            doInput = true
            doOutput = body != null
            setRequestProperty("apikey", key)
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
            accessToken?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setFixedLengthStreamingMode(body.toByteArray(StandardCharsets.UTF_8).size)
            }
        }
        try {
            if (body != null) connection.outputStream.use {
                it.write(body.toByteArray(StandardCharsets.UTF_8))
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                ?: return status to ""
            val text = stream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(2048)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_RESPONSE_BYTES) { "Supreme Auth response was too large." }
                    output.write(buffer, 0, count)
                }
                output.toString(StandardCharsets.UTF_8.name())
            }
            return status to text
        } finally {
            connection.disconnect()
        }
    }

    private fun assertWorkerThread() {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Supreme Auth network operations must run off the Android UI thread."
        }
    }

    class AuthException(message: String) : IllegalStateException(message)

    companion object {
        private const val MAX_RESPONSE_BYTES = 32 * 1024
        private val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
    }
}
