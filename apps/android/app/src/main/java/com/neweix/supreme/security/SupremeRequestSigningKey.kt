package com.neweix.supreme.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64 as AndroidBase64
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.net.URI
import java.net.URLDecoder
import java.util.Locale

/**
 * Separate, hardware-backed transport key for signing ordinary Supreme API
 * requests. It is intentionally distinct from SupremeKeyAttestation's
 * biometric-per-operation approval key.
 *
 * Server-side request-key enrollment and API enforcement must be deployed
 * before callers use this class for privileged requests.
 */
internal object SupremeRequestSigningKey {
    private const val KEY_ALIAS = "com.neweix.supreme.request-signing.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ATTESTATION_DOMAIN = "NEWEIX-SUPREME-ATTESTATION-V1"
    private const val REQUEST_DOMAIN = "NEWEIX-SUPREME-API-REQUEST-V1"

    data class AttestationMaterial(
        val certificateChainBase64: List<String>,
        val proofSignatureBase64: String,
    )

    data class SignedHeaders(
        val challengeId: String,
        val timestamp: String,
        val signatureBase64: String,
    )

    /**
     * Generates a non-exportable P-256 key with a server challenge embedded in
     * its Android Key Attestation certificate. No per-operation biometric is
     * required for this transport key; Android app UID isolation and the
     * existing Supreme app lock gate access. Hardware security and app identity
     * must be verified by the server before the key is registered.
     */
    @Synchronized
    fun createAttestedKey(challengeId: String, challenge: ByteArray): AttestationMaterial {
        require(UUID_V4.matches(challengeId)) { "Invalid request-key challenge ID." }
        require(challenge.size == 32) { "Request-key challenge must be 32 bytes." }

        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        store.deleteEntry(KEY_ALIAS)
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge.copyOf())
                .setUserAuthenticationRequired(false)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()

            val chain = store.getCertificateChain(KEY_ALIAS)
                ?: error("Android did not return a request-key attestation chain.")
            require(chain.size in 3..10) { "A verifiable hardware attestation chain is unavailable." }

            val encodedChallenge = base64Url(challenge)
            val payload = "$ATTESTATION_DOMAIN\n$challengeId\n$encodedChallenge"
                .toByteArray(StandardCharsets.UTF_8)
            val privateKey = store.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
                ?: error("Android request-signing key is unavailable.")
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(payload)
                sign()
            }
            return AttestationMaterial(
                certificateChainBase64 = chain.map { AndroidBase64.encodeToString(it.encoded, AndroidBase64.NO_WRAP) },
                proofSignatureBase64 = AndroidBase64.encodeToString(signature, AndroidBase64.NO_WRAP),
            )
        } catch (error: Exception) {
            store.deleteEntry(KEY_ALIAS)
            throw error
        }
    }

    /**
     * Signs the exact bytes and request target that the HTTP transport will
     * send. Callers must not re-serialize JSON after computing this signature.
     */
    @Synchronized
    fun signRequest(
        challengeId: String,
        nonce: ByteArray,
        method: String,
        pathAndQuery: String,
        bodyBytes: ByteArray,
        timestampSeconds: Long,
    ): SignedHeaders {
        require(UUID_V4.matches(challengeId)) { "Invalid request challenge ID." }
        require(nonce.size == 32) { "Invalid request nonce." }
        require(method.matches(Regex("^[A-Z]{3,10}$"))) { "Invalid HTTP method." }
        require(timestampSeconds > 0) { "Invalid request timestamp." }
        val target = canonicalTarget(pathAndQuery)
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(bodyBytes).toHex()
        val payload = listOf(
            REQUEST_DOMAIN,
            challengeId,
            base64Url(nonce),
            method,
            target,
            bodyHash,
            timestampSeconds.toString(),
        ).joinToString("\n").toByteArray(StandardCharsets.UTF_8)

        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = store.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            ?: throw IllegalStateException("Supreme request-signing key is unavailable. Re-enroll this device.")
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(payload)
            sign()
        }
        return SignedHeaders(
            challengeId = challengeId,
            timestamp = timestampSeconds.toString(),
            signatureBase64 = AndroidBase64.encodeToString(signature, AndroidBase64.NO_WRAP),
        )
    }

    @Synchronized
    fun isKeyAvailable(): Boolean {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return store.containsAlias(KEY_ALIAS) && store.getKey(KEY_ALIAS, null) is java.security.PrivateKey
    }

    @Synchronized
    fun delete() {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
            deleteEntry(KEY_ALIAS)
        }
    }

    internal fun canonicalTarget(value: String): String {
        require(value.isNotEmpty() && value.length <= 4096 && value.all { it.code in 0x21..0x7e }) { "Invalid request target." }
        require(value.startsWith("/") && !value.startsWith("//")) { "Request target must be an absolute path." }
        require(!value.contains('#') && !value.contains('\\')) { "Request target contains forbidden characters." }
        require(!Regex("(?i)%2f|%5c").containsMatchIn(value)) { "Encoded path separators are forbidden." }
        require(!Regex("%(?![0-9A-F]{2})").containsMatchIn(value)) { "Percent escapes must be uppercase and canonical." }
        val uri = URI(value)
        require(uri.isAbsolute.not() && uri.rawAuthority == null && uri.rawFragment == null) {
            "Absolute URLs and fragments are forbidden."
        }
        val rawPath = uri.rawPath ?: throw IllegalArgumentException("Request path is missing.")
        require(rawPath.startsWith("/") && !rawPath.contains("//")) { "Request path is not canonical." }
        require(!Regex("(?i)%2e").containsMatchIn(rawPath)) { "Encoded dot segments are forbidden." }
        val decodedSegments = rawPath.split("/")
        require(decodedSegments.none { it == "." || it == ".." }) {
            "Dot segments are forbidden."
        }
        val queryKeys = HashSet<String>()
        uri.rawQuery?.split("&")?.forEach { pair ->
            val key = URLDecoder.decode(pair.substringBefore("="), StandardCharsets.UTF_8.name())
            require(queryKeys.add(key)) { "Duplicate query parameters are forbidden." }
        }
        return rawPath + (uri.rawQuery?.let { "?$it" } ?: "")
    }

    private fun base64Url(bytes: ByteArray): String =
        AndroidBase64.encodeToString(bytes, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }

    private val UUID_V4 = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
}
