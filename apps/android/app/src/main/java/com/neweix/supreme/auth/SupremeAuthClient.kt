package com.neweix.supreme.auth

import com.neweix.supreme.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Base64

internal class SupremeAuthException(
    message: String,
    val statusCode: Int,
) : Exception(message)

internal object SupremeAuthClient {
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 20_000
    private const val MAX_RESPONSE_BYTES = 64 * 1024

    data class AuthSession(
        val accessToken: String,
        val refreshToken: String,
        val userId: String,
        val assuranceLevel: String,
        val authTime: Long,
        val sessionId: String,
    )

    data class TotpFactor(
        val id: String,
        val name: String,
    )

    data class Service(
        val id: String,
        val name: String,
        val status: String,
        val riskTier: String,
        val description: String,
    )

    fun signIn(email: String, password: String): AuthSession {
        require(email.length <= 320 && email.contains("@")) { "Enter the Supreme account email." }
        require(password.length in 1..256) { "Enter the Supreme account password." }
        val payload = JSONObject()
            .put("email", email.trim())
            .put("password", password)
        return parseSession(
            request("POST", "/auth/v1/token?grant_type=password", body = payload),
            stage = "Password sign-in",
        )
    }

    fun verifiedTotpFactors(accessToken: String): List<TotpFactor> {
        val response = request("GET", "/functions/v1/supreme-session-api/factors", accessToken)
        // The Supreme session API returns only this account’s verified factors.
        val candidates = response.optJSONArray("factors") ?: JSONArray()

        val factors = ArrayList<TotpFactor>()
        for (i in 0 until candidates.length()) {
            val factor = candidates.optJSONObject(i) ?: continue
            if (factor.optString("factor_type") != "totp" ||
                factor.optString("status") != "verified"
            ) continue
            val id = factor.optString("id")
            if (!UUID_PATTERN.matches(id)) continue
            factors.add(TotpFactor(id, factor.optString("friendly_name", "Authenticator")))
        }
        return factors
    }

    fun createTotpChallenge(accessToken: String, factorId: String): String {
        require(UUID_PATTERN.matches(factorId)) { "Invalid Supreme MFA factor." }
        val response = request(
            "POST",
            "/auth/v1/factors/$factorId/challenge",
            accessToken,
            JSONObject(),
        )
        val challengeId = response.optString("id")
        require(UUID_PATTERN.matches(challengeId)) { "Supreme MFA challenge could not be created." }
        return challengeId
    }

    fun verifyTotp(
        accessToken: String,
        factorId: String,
        challengeId: String,
        code: String,
        fallbackRefreshToken: String,
        expectedUserId: String,
    ): AuthSession {
        require(UUID_PATTERN.matches(factorId) && UUID_PATTERN.matches(challengeId)) {
            "Invalid Supreme MFA challenge."
        }
        require(code.matches(Regex("^[0-9]{6,8}$"))) { "Enter the current authenticator code." }
        val response = request(
            "POST",
            "/auth/v1/factors/$factorId/verify",
            accessToken,
            JSONObject()
                .put("challenge_id", challengeId)
                .put("code", code),
        )
        return parseSession(
            response,
            stage = "Authenticator verification",
            fallbackRefreshToken = fallbackRefreshToken,
            expectedUserId = expectedUserId,
        )
    }

    fun refresh(refreshToken: String): AuthSession {
        require(refreshToken.length in 20..8192) { "Supreme session is invalid. Sign in again." }
        val response = request(
            "POST",
            "/auth/v1/token?grant_type=refresh_token",
            body = JSONObject().put("refresh_token", refreshToken),
        )
        return parseSession(response, stage = "Session refresh")
    }

    fun signOut(accessToken: String) {
        request("POST", "/auth/v1/logout?scope=global", accessToken, JSONObject())
    }

    fun verifyDeviceSession(accessToken: String) {
        val response = request(
            "GET",
            "/functions/v1/supreme-session-api",
            accessToken = accessToken,
        )
        require(response.optBoolean("authenticated", false) &&
            response.optBoolean("device_session_active", false)
        ) {
            "The server has not authorized this Supreme device session."
        }
        val session = response.optJSONObject("session")
            ?: throw IllegalStateException("Supreme device session details are missing.")
        val claims = decodeClaims(accessToken).optJSONObject("supreme_app_session")
            ?: throw IllegalStateException("The signed Supreme device-session claim is missing.")
        require(claims.optString("status") == "active" &&
            claims.optString("session_id") == session.optString("session_id") &&
            claims.optString("device_id") == session.optString("device_id")
        ) {
            "The signed Supreme device-session claim does not match the active server session."
        }
    }

    fun revokeDeviceSession(accessToken: String) {
        request(
            "DELETE",
            "/functions/v1/supreme-session-api",
            accessToken = accessToken,
        )
    }

    fun listServices(accessToken: String): List<Service> {
        val response = request(
            "GET",
            "/functions/v1/supreme-registry-api/v1/services?limit=100",
            accessToken = accessToken,
        )
        val rows = response.optJSONArray("services") ?: JSONArray()
        val result = ArrayList<Service>()
        for (i in 0 until rows.length()) {
            val row = rows.optJSONObject(i) ?: continue
            result.add(
                Service(
                    id = row.optString("service_id", "unknown"),
                    name = row.optString("display_name", "Unnamed service"),
                    status = row.optString("status", "unknown"),
                    riskTier = row.optString("risk_tier", "unclassified"),
                    description = row.optString("description", ""),
                ),
            )
        }
        return result
    }

    data class ControlRequest(
        val id: String,
        val requestType: String,
        val serviceId: String?,
        val action: String,
        val status: String,
        val createdAt: String,
        val expiresAt: String,
    )

    fun listPendingRequests(accessToken: String): List<ControlRequest> {
        val response = request(
            "GET",
            "/functions/v1/supreme-registry-api/v1/control-requests?status=pending&limit=50",
            accessToken = accessToken,
        )
        val rows = response.optJSONArray("control_requests") ?: JSONArray()
        val result = ArrayList<ControlRequest>()
        for (i in 0 until rows.length()) {
            val row = rows.optJSONObject(i) ?: continue
            val id = row.optString("id")
            if (!UUID_PATTERN.matches(id)) continue
            result.add(
                ControlRequest(
                    id = id,
                    requestType = row.optString("request_type", "operation"),
                    serviceId = row.optString("service_id").takeIf { it.isNotBlank() && it != "null" },
                    action = row.optString("action", "unknown"),
                    status = row.optString("status", "unknown"),
                    createdAt = row.optString("created_at", ""),
                    expiresAt = row.optString("expires_at", ""),
                ),
            )
        }
        return result
    }

    fun decideControlRequest(
        accessToken: String,
        requestId: String,
        decision: String,
        reason: String? = null,
    ) {
        require(UUID_PATTERN.matches(requestId)) { "Invalid Supreme request ID." }
        require(decision == "approve" || decision == "reject") { "Invalid Supreme decision." }
        if (decision == "reject") {
            require(!reason.isNullOrBlank() && reason.length in 8..500) {
                "A rejection reason of at least 8 characters is required."
            }
        }
        request(
            "POST",
            "/functions/v1/supreme-registry-api/v1/control-requests/$requestId/decision",
            accessToken,
            JSONObject().put("decision", decision).apply {
                if (!reason.isNullOrBlank()) put("reason", reason)
            },
        )
    }

    private fun parseSession(
        response: JSONObject,
        stage: String,
        fallbackRefreshToken: String? = null,
        expectedUserId: String? = null,
    ): AuthSession {
        val access = response.optString("access_token")
            .takeIf { it.length in 40..16_384 }
        val responseRefresh = response.optString("refresh_token")
            .takeIf { it.length in 20..8192 }
        // Supabase MFA upgrades may omit a replacement refresh token in a
        // response. Reuse only the refresh token from this same pre-MFA
        // session; the caller must still refresh it and prove AAL2 continuity
        // with the server before opening any privileged screen.
        val refresh = responseRefresh ?: fallbackRefreshToken
            ?.takeIf { it.length in 20..8192 }

        val responseUserId = response.optJSONObject("user")
            ?.optString("id")
            .orEmpty()
        val userId = if (UUID_PATTERN.matches(responseUserId)) {
            responseUserId
        } else if (access != null && expectedUserId != null &&
            UUID_PATTERN.matches(expectedUserId)
        ) {
            // Resolve a missing user object through Supabase's authenticated
            // /user endpoint instead of trusting an unverified JWT subject.
            runCatching {
                request("GET", "/auth/v1/user", accessToken = access)
                    .optString("id")
                    .takeIf { it == expectedUserId && UUID_PATTERN.matches(it) }
            }.getOrNull().orEmpty()
        } else {
            ""
        }

        val missing = mutableListOf<String>()
        if (access == null) missing += "access_token"
        if (refresh == null) missing += "refresh_token"
        if (!UUID_PATTERN.matches(userId)) missing += "user.id"
        if (missing.isNotEmpty()) {
            throw IllegalStateException(
                "$stage response was incomplete. Missing or invalid: ${missing.joinToString(", ")}.",
            )
        }

        val claims = decodeClaims(access!!)
        val assurance = claims.optString("aal", "aal1")
        val authTime = claims.optLong("auth_time", 0L)
        val sessionId = claims.optString("session_id")
        require(assurance == "aal1" || assurance == "aal2") {
            "Supreme authentication assurance could not be verified."
        }
        require(UUID_PATTERN.matches(sessionId)) { "Supreme session identifier is invalid." }

        return AuthSession(access, refresh!!, userId, assurance, authTime, sessionId)
    }

    private fun decodeClaims(accessToken: String): JSONObject {
        val parts = accessToken.split(".")
        require(parts.size == 3) { "Supreme authentication token is malformed." }
        val payload = Base64.getUrlDecoder().decode(parts[1])
        require(payload.size <= 16 * 1024) { "Supreme authentication token is too large." }
        return JSONObject(String(payload, StandardCharsets.UTF_8))
    }

    private fun request(
        method: String,
        path: String,
        accessToken: String? = null,
        body: JSONObject? = null,
    ): JSONObject {
        val url = URL(BuildConfig.SUPABASE_URL.trimEnd('/') + path)
        require(url.protocol == "https" && url.host == "grhybvlhdnzlopwbaqun.supabase.co" &&
            url.port == -1 && url.userInfo == null
        ) { "Supreme authentication endpoint is not approved." }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            useCaches = false
            doInput = true
            doOutput = body != null
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
            setRequestProperty("apikey", BuildConfig.SUPABASE_PUBLISHABLE_KEY)
            if (!accessToken.isNullOrBlank()) {
                setRequestProperty("Authorization", "Bearer $accessToken")
            }
            if (body != null) {
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }

        try {
            if (body != null) {
                val bytes = body.toString().toByteArray(StandardCharsets.UTF_8)
                require(bytes.size <= 16 * 1024) { "Supreme request is too large." }
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { it.write(bytes) }
            }

            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            if (stream == null) {
                if (status in 200..299) return JSONObject()
                throw SupremeAuthException("Supreme service rejected the request (HTTP $status).", status)
            }

            val responseBytes = stream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(2048)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_RESPONSE_BYTES) {
                        throw SupremeAuthException("Supreme service response exceeded the allowed size.", 502)
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            val text = String(responseBytes, StandardCharsets.UTF_8)
            val parsed = try {
                if (text.isBlank()) JSONObject() else JSONObject(text)
            } catch (_: Exception) {
                throw SupremeAuthException("Supreme service returned an invalid response.", 502)
            }

            if (status !in 200..299) {
                val message = parsed.optString("msg")
                    .ifBlank { parsed.optString("message") }
                    .ifBlank { parsed.optString("error_description") }
                    .ifBlank { parsed.optString("error") }
                    .ifBlank { "Supreme authentication failed. Check the account details and try again." }
                throw SupremeAuthException(message.take(240), status)
            }
            return parsed
        } finally {
            connection.disconnect()
        }
    }

    private val UUID_PATTERN = Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        RegexOption.IGNORE_CASE,
    )
}
