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
        require(refreshToken.isNotBlank() && refreshToken.length <= 8192 && refreshToken != "null") { "Supreme session is invalid. Sign in again." }
        val response = request(
            "POST",
            "/auth/v1/token?grant_type=refresh_token",
            body = JSONObject().put("refresh_token", refreshToken),
        )
        return parseSession(response, stage = "Session refresh")
    }

    data class BreakGlassRecoveryRequest(
        val requestId: String,
        val availableAt: String,
        val expiresAt: String,
        val notificationDelivered: Boolean,
    )

    fun beginBreakGlassRecovery(accessToken: String, recoveryMaterial: String): BreakGlassRecoveryRequest {
        require(accessToken.isNotBlank()) { "A fresh Supreme AAL2 session is required." }
        require(Regex("^[a-f0-9]{64}$").matches(recoveryMaterial)) {
            "Offline recovery material must be 64 lowercase hexadecimal characters."
        }
        val response = request(
            "POST",
            "/functions/v1/supreme-session-api/recovery/request",
            accessToken,
            JSONObject().put("recovery_material", recoveryMaterial),
        )
        val requestId = response.optString("request_id")
        val availableAt = response.optString("available_at")
        val expiresAt = response.optString("expires_at")
        require(UUID_PATTERN.matches(requestId) && availableAt.isNotBlank() && expiresAt.isNotBlank()) {
            "Supreme recovery request response was incomplete."
        }
        return BreakGlassRecoveryRequest(
            requestId = requestId,
            availableAt = availableAt,
            expiresAt = expiresAt,
            notificationDelivered = response.optBoolean("notification_delivered", false),
        )
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

    data class TrustedDevice(
        val id: String,
        val status: String,
        val securityLevel: String,
        val attestedAt: String,
        val lastSeenAt: String?,
        val createdAt: String,
        val activeSessions: Int,
        val isCurrentDevice: Boolean,
    )

    data class DeviceRevocationChallenge(
        val id: String,
        val nonce: String,
        val deviceId: String,
    )

    fun listTrustedDevices(accessToken: String): List<TrustedDevice> {
        val response = request("GET", "/functions/v1/supreme-session-api/devices", accessToken = accessToken)
        val rows = response.optJSONArray("devices") ?: JSONArray()
        val result = ArrayList<TrustedDevice>()
        for (i in 0 until rows.length()) {
            val row = rows.optJSONObject(i) ?: continue
            val id = row.optString("device_id")
            if (!UUID_PATTERN.matches(id)) continue
            result.add(TrustedDevice(
                id = id,
                status = row.optString("status", "unknown"),
                securityLevel = row.optString("security_level", "unknown"),
                attestedAt = row.optString("attested_at", ""),
                lastSeenAt = row.optString("last_seen_at").takeIf { it.isNotBlank() && it != "null" },
                createdAt = row.optString("created_at", ""),
                activeSessions = row.optInt("active_sessions", 0).coerceAtLeast(0),
                isCurrentDevice = row.optBoolean("is_current_device", false),
            ))
        }
        return result
    }

    fun issueDeviceRevocationChallenge(accessToken: String, deviceId: String): DeviceRevocationChallenge {
        require(UUID_PATTERN.matches(deviceId)) { "Invalid Supreme device ID." }
        val response = request(
            "POST",
            "/functions/v1/supreme-session-api/devices/" + deviceId + "/revoke/challenge",
            accessToken,
            JSONObject(),
        )
        val id = response.optString("challenge_id")
        val nonce = response.optString("nonce")
        val returnedDeviceId = response.optString("device_id")
        require(UUID_PATTERN.matches(id) && UUID_PATTERN.matches(returnedDeviceId) &&
            returnedDeviceId == deviceId && Regex("^[A-Za-z0-9_-]{43}$").matches(nonce)
        ) { "Supreme device revocation challenge was invalid." }
        return DeviceRevocationChallenge(id, nonce, returnedDeviceId)
    }

    fun revokeTrustedDevice(
        accessToken: String,
        challenge: DeviceRevocationChallenge,
        signature: String,
    ) {
        require(UUID_PATTERN.matches(challenge.id) && UUID_PATTERN.matches(challenge.deviceId))
        require(signature.length in 80..160 && Regex("^[A-Za-z0-9+/]+={0,2}$").matches(signature))
        request(
            "POST",
            "/functions/v1/supreme-session-api/devices/" + challenge.deviceId + "/revoke",
            accessToken,
            JSONObject()
                .put("challenge_id", challenge.id)
                .put("nonce", challenge.nonce)
                .put("signature", signature),
        )
    }

    data class EnrollmentRequest(
        val id: String,
        val deviceId: String,
        val securityLevel: String,
        val requestedAt: String,
        val expiresAt: String,
    )

    data class EnrollmentApprovalChallenge(
        val id: String,
        val nonce: String,
        val enrollmentRequestId: String,
        val deviceId: String,
    )

    fun listPendingEnrollments(accessToken: String): List<EnrollmentRequest> {
        val response = request(
            "GET",
            "/functions/v1/supreme-session-api/enrollments",
            accessToken = accessToken,
        )
        val rows = response.optJSONArray("enrollment_requests") ?: JSONArray()
        val result = ArrayList<EnrollmentRequest>()
        for (i in 0 until rows.length()) {
            val row = rows.optJSONObject(i) ?: continue
            val id = row.optString("request_id")
            val deviceId = row.optString("device_id")
            if (!UUID_PATTERN.matches(id) || !UUID_PATTERN.matches(deviceId)) continue
            result.add(
                EnrollmentRequest(
                    id = id,
                    deviceId = deviceId,
                    securityLevel = row.optString("security_level", "unknown"),
                    requestedAt = row.optString("requested_at", ""),
                    expiresAt = row.optString("expires_at", ""),
                ),
            )
        }
        return result
    }

    fun issueEnrollmentApprovalChallenge(
        accessToken: String,
        enrollmentRequestId: String,
    ): EnrollmentApprovalChallenge {
        require(UUID_PATTERN.matches(enrollmentRequestId)) { "Invalid enrollment request." }
        val response = request(
            "POST",
            "/functions/v1/supreme-session-api/enrollments/$enrollmentRequestId/challenge",
            accessToken,
            JSONObject(),
        )
        val id = response.optString("challenge_id")
        val nonce = response.optString("nonce")
        val requestId = response.optString("enrollment_request_id")
        val deviceId = response.optString("device_id")
        require(UUID_PATTERN.matches(id) && UUID_PATTERN.matches(requestId) &&
            UUID_PATTERN.matches(deviceId) && Regex("^[A-Za-z0-9_-]{43}$").matches(nonce)
        ) { "Supreme enrollment approval challenge was invalid." }
        return EnrollmentApprovalChallenge(id, nonce, requestId, deviceId)
    }

    fun approveEnrollment(
        accessToken: String,
        challenge: EnrollmentApprovalChallenge,
        signature: String,
    ) {
        require(UUID_PATTERN.matches(challenge.id) &&
            UUID_PATTERN.matches(challenge.enrollmentRequestId) &&
            UUID_PATTERN.matches(challenge.deviceId)
        ) { "Invalid enrollment approval challenge." }
        require(signature.length in 80..160 &&
            Regex("^[A-Za-z0-9+/]+={0,2}$").matches(signature)
        ) { "Supreme enrollment approval signature is invalid." }
        request(
            "POST",
            "/functions/v1/supreme-session-api/enrollments/${challenge.enrollmentRequestId}/approve",
            accessToken,
            JSONObject()
                .put("challenge_id", challenge.id)
                .put("nonce", challenge.nonce)
                .put("device_id", challenge.deviceId)
                .put("signature", signature),
        )
    }

    data class DecisionChallenge(
        val id: String,
        val nonce: String,
    )

    fun issueControlDecisionChallenge(
        accessToken: String,
        requestId: String,
        decision: String,
        reason: String?,
    ): DecisionChallenge {
        require(UUID_PATTERN.matches(requestId)) { "Invalid Supreme request ID." }
        require(decision == "approve" || decision == "reject") { "Invalid Supreme decision." }
        val body = JSONObject().put("decision", decision).apply {
            if (!reason.isNullOrBlank()) put("reason", reason)
        }
        val response = request(
            "POST",
            "/functions/v1/supreme-registry-api/v1/control-requests/$requestId/decision-challenge",
            accessToken,
            body,
        )
        val id = response.optString("challenge_id")
        val nonce = response.optString("nonce")
        require(UUID_PATTERN.matches(id) && Regex("^[A-Za-z0-9_-]{43}$").matches(nonce)) {
            "Supreme decision challenge response was invalid."
        }
        return DecisionChallenge(id, nonce)
    }

    fun decideControlRequest(
        accessToken: String,
        requestId: String,
        decision: String,
        reason: String? = null,
        challengeId: String,
        nonce: String,
        signature: String,
    ) {
        require(UUID_PATTERN.matches(requestId)) { "Invalid Supreme request ID." }
        require(decision == "approve" || decision == "reject") { "Invalid Supreme decision." }
        if (decision == "reject") {
            require(!reason.isNullOrBlank() && reason.length in 8..500) {
                "A rejection reason of at least 8 characters is required."
            }
        }
        require(UUID_PATTERN.matches(challengeId) && Regex("^[A-Za-z0-9_-]{43}$").matches(nonce))
        require(signature.length in 80..160 && Regex("^[A-Za-z0-9+/]+={0,2}$").matches(signature))
        request(
            "POST",
            "/functions/v1/supreme-registry-api/v1/control-requests/$requestId/decision",
            accessToken,
            JSONObject()
                .put("decision", decision)
                .put("challenge_id", challengeId)
                .put("nonce", nonce)
                .put("signature", signature)
                .apply {
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
            .takeIf { it.isNotBlank() && it.length <= 8192 && it != "null" }
        // Supabase MFA upgrades may omit a replacement refresh token in a
        // response. Reuse only the refresh token from this same pre-MFA
        // session; the caller must still refresh it and prove AAL2 continuity
        // with the server before opening any privileged screen.
        val refresh = responseRefresh ?: fallbackRefreshToken
            ?.takeIf { it.isNotBlank() && it.length <= 8192 && it != "null" }

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
