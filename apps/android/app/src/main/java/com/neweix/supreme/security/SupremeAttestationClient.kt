package com.neweix.supreme.security

import android.os.Looper
import com.neweix.supreme.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Native transport for the server-issued Supreme Android attestation challenge.
 *
 * This only proves app/device-key possession to the attestation verifier. A
 * successful result is NOT a Supabase session, login, role grant, or dashboard
 * authorization. Password and AAL2 MFA remain separate mandatory gates.
 */
internal object SupremeAttestationClient {
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 25_000
    private const val MAX_RESPONSE_BYTES = 16 * 1024
    private const val MAX_CERTIFICATES = 10
    private val ORIGIN = BuildConfig.SUPABASE_URL.trimEnd('/')
    private const val APPROVED_HOST = "grhybvlhdnzlopwbaqun.supabase.co"

    data class Verification(
        val securityLevel: String,
        val provisioningMethod: String,
        val proofOfPossessionVerified: Boolean,
    )

    data class PreparedVerification internal constructor(
        internal val challengeId: String,
        internal val challengeEncoded: String,
        internal val material: SupremeKeyAttestation.Material,
    )

    /**
     * Fetches the server challenge and prepares an attested key operation.
     * The caller MUST complete material.proofSigner through BIOMETRIC_STRONG
     * BiometricPrompt.CryptoObject before submitting the proof.
     */
    fun prepareVerification(accessToken: String): PreparedVerification {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Supreme attestation must run off the Android UI thread."
        }
        val challengeResponse = postJson("/functions/v1/supreme-session-api/challenge", null, accessToken)
        if (challengeResponse.first != HttpURLConnection.HTTP_OK) {
            throw IllegalStateException("Supreme device challenge could not be issued.")
        }
        val challengeJson = JSONObject(challengeResponse.second)
        check(challengeJson.optBoolean("success", false)) {
            "Supreme device challenge response was invalid."
        }
        val challengeId = challengeJson.optString("challenge_id")
        require(UUID_V4.matches(challengeId)) { "Supreme device challenge ID was invalid." }
        val challengeEncoded = challengeJson.optString("challenge")
        require(challengeEncoded.isNotEmpty() && challengeEncoded.length <= 64) {
            "Supreme device challenge was invalid."
        }
        val challenge = Base64.getUrlDecoder().decode(challengeEncoded)
        require(challenge.size == 32 &&
            Base64.getUrlEncoder().withoutPadding().encodeToString(challenge) == challengeEncoded
        ) { "Supreme device challenge was not canonical." }
        val material = SupremeKeyAttestation.create(challengeId, challenge)
        require(material.certificateChainBase64.size in 3..MAX_CERTIFICATES) {
            "This device did not provide a usable Android attestation chain."
        }
        return PreparedVerification(challengeId, challengeEncoded, material)
    }

    /**
     * Completes server verification using a proof signature produced only after
     * the prepared Signature was authorized by Android BIOMETRIC_STRONG.
     */
    fun completeVerification(
        accessToken: String,
        prepared: PreparedVerification,
        proofSignatureBase64: String,
    ): Verification {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Supreme attestation must run off the Android UI thread."
        }
        require(accessToken.isNotBlank()) { "Supreme AAL2 access token is required." }
        require(proofSignatureBase64.length in 80..160 &&
            Regex("^[A-Za-z0-9+/]+={0,2}$").matches(proofSignatureBase64)
        ) { "Supreme biometric attestation proof is malformed." }

        val certificateArray = JSONArray()
        prepared.material.certificateChainBase64.forEach { certificateArray.put(it) }
        val verifyPayload = JSONObject()
            .put("challenge_id", prepared.challengeId)
            .put("challenge", prepared.challengeEncoded)
            .put("certificate_chain", certificateArray)
            .put("proof_signature", proofSignatureBase64)
        val response = postJson(
            "/functions/v1/supreme-session-api/issue",
            verifyPayload.toString().toByteArray(StandardCharsets.UTF_8),
            accessToken,
        )
        if (response.first != HttpURLConnection.HTTP_OK) {
            throw IllegalStateException(
                "Supreme device verification was rejected (HTTP ${response.first}).",
            )
        }
        val result = JSONObject(response.second)
        check(result.optBoolean("registered", false)) {
            "Supreme device-bound session registration was not confirmed."
        }
        return Verification(
            securityLevel = when (result.optString("security_level")) {
                "strongbox" -> "STRONG_BOX"
                "trusted_environment" -> "TRUSTED_ENVIRONMENT"
                else -> "unknown"
            },
            provisioningMethod = result.optString("provisioning_method", "unknown"),
            proofOfPossessionVerified = true,
        )
    }

    /**
     * Enrolls a second, non-exportable hardware key dedicated to API request
     * signatures. The existing biometric-per-use approval key is untouched.
     * Must run off the UI thread after the primary device session is registered.
     */
    fun enrollRequestSigningKey(accessToken: String): Verification {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Supreme request-key enrollment must run off the Android UI thread."
        }
        require(accessToken.isNotBlank()) { "Supreme AAL2 access token is required." }

        val challengeResponse = postJson("/functions/v1/supreme-session-api/challenge", null, accessToken)
        if (challengeResponse.first != HttpURLConnection.HTTP_OK) {
            throw IllegalStateException("Supreme request-key challenge could not be issued.")
        }
        val challengeJson = JSONObject(challengeResponse.second)
        check(challengeJson.optBoolean("success", false)) {
            "Supreme request-key challenge response was invalid."
        }
        val challengeId = challengeJson.optString("challenge_id")
        require(UUID_V4.matches(challengeId)) { "Supreme request-key challenge ID was invalid." }
        val challengeEncoded = challengeJson.optString("challenge")
        require(challengeEncoded.isNotEmpty() && challengeEncoded.length <= 64) {
            "Supreme request-key challenge was invalid."
        }
        val challenge = Base64.getUrlDecoder().decode(challengeEncoded)
        require(challenge.size == 32 &&
            Base64.getUrlEncoder().withoutPadding().encodeToString(challenge) == challengeEncoded
        ) { "Supreme request-key challenge was not canonical." }

        val material = SupremeRequestSigningKey.createAttestedKey(challengeId, challenge)
        val certificates = JSONArray()
        material.certificateChainBase64.forEach { certificates.put(it) }
        val payload = JSONObject()
            .put("challenge_id", challengeId)
            .put("challenge", challengeEncoded)
            .put("certificate_chain", certificates)
            .put("proof_signature", material.proofSignatureBase64)
            .put("key_purpose", "request_signing")
        val response = postJson(
            "/functions/v1/supreme-session-api/issue",
            payload.toString().toByteArray(StandardCharsets.UTF_8),
            accessToken,
        )
        if (response.first != HttpURLConnection.HTTP_OK) {
            SupremeRequestSigningKey.delete()
            throw IllegalStateException(
                "Supreme request-signing key registration was rejected (HTTP ${response.first}).",
            )
        }
        val result = JSONObject(response.second)
        check(result.optBoolean("registered", false) &&
            result.optString("key_purpose") == "request_signing"
        ) {
            SupremeRequestSigningKey.delete()
            "Supreme request-signing key registration was not confirmed."
        }
        return Verification(
            securityLevel = when (result.optString("security_level")) {
                "strongbox" -> "STRONG_BOX"
                "trusted_environment" -> "TRUSTED_ENVIRONMENT"
                else -> "unknown"
            },
            provisioningMethod = result.optString("provisioning_method", "unknown"),
            proofOfPossessionVerified = true,
        )
    }

    private fun postJson(path: String, body: ByteArray?, accessToken: String? = null): Pair<Int, String> {
        val url = URL(ORIGIN + path)
        require(
            url.protocol == "https" &&
                url.host == APPROVED_HOST &&
                url.port == -1 &&
                url.userInfo == null
        ) {
            "Supreme attestation endpoint origin is invalid."
        }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            useCaches = false
            doInput = true
            doOutput = body != null
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
            setRequestProperty("apikey", BuildConfig.SUPABASE_PUBLISHABLE_KEY)
            accessToken?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setFixedLengthStreamingMode(body.size)
            }
        }

        try {
            if (body != null) {
                connection.outputStream.use { output -> output.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                ?: throw IllegalStateException("Supreme attestation endpoint returned no response.")
            val response = stream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(2048)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_RESPONSE_BYTES) {
                        "Supreme attestation response was too large."
                    }
                    output.write(buffer, 0, count)
                }
                output.toString(StandardCharsets.UTF_8.name())
            }
            return status to response
        } finally {
            connection.disconnect()
        }
    }

    private val UUID_V4 = Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
}
