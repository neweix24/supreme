package com.neweix.supreme.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Creates a fresh Android Keystore key whose certificate chain carries the
 * server-provided Android Key Attestation challenge.
 *
 * This class deliberately does not decide whether an attestation is trusted.
 * The certificate chain and proof signature must be verified by the server
 * against Google's roots, current revocation data, app identity and challenge.
 */
internal object SupremeKeyAttestation {
    private const val KEY_ALIAS = "com.neweix.supreme.attestation.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val PROOF_DOMAIN = "NEWEIX-SUPREME-ATTESTATION-V1"

    data class Material(
        val certificateChainBase64: List<String>,
        val challengeProofBase64: String,
    )

    /**
     * Generates a non-exportable P-256 signing key and returns its attestation
     * chain in leaf-to-root order, plus a signature proving possession of the
     * attested private key for this exact server challenge.
     *
     * The proof payload is UTF-8:
     *   NEWEIX-SUPREME-ATTESTATION-V1\n<challenge UUID>\n<base64url challenge>
     *
     * The signature is SHA256withECDSA (ASN.1 DER encoded).
     */
    @Synchronized
    fun create(challengeId: String, challenge: ByteArray): Material {
        require(Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").matches(challengeId)) {
            "The server attestation challenge ID is invalid."
        }
        require(challenge.size == 32) {
            "The server attestation challenge must contain exactly 32 bytes."
        }

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.deleteEntry(KEY_ALIAS)

        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )
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

            val chain = keyStore.getCertificateChain(KEY_ALIAS)
                ?: error("Android did not return an attestation certificate chain.")

            require(chain.size >= 2) {
                "A verifiable hardware attestation certificate chain is unavailable on this device."
            }

            val challengeEncoded = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(challenge)
            val proofPayload = "$PROOF_DOMAIN\n$challengeId\n$challengeEncoded"
                .toByteArray(StandardCharsets.UTF_8)

            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
                ?: error("Android Keystore did not return the attestation private key.")
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(proofPayload)
            val proof = signer.sign()

            return Material(
                certificateChainBase64 = chain.map { certificate ->
                    Base64.getEncoder().encodeToString(certificate.encoded)
                },
                challengeProofBase64 = Base64.getEncoder().encodeToString(proof),
            )
        } catch (error: Exception) {
            keyStore.deleteEntry(KEY_ALIAS)
            throw error
        }
    }

    /**
     * Signs a server-issued, one-time Supreme control-decision challenge with
     * the same non-exportable key whose public key was verified at registration.
     * The server binds the signature to the request, decision and reason digest.
     */
    @Synchronized
    fun signControlDecision(
        challengeId: String,
        nonceBase64Url: String,
        requestId: String,
        decision: String,
        reason: String?,
    ): String {
        require(Regex("^[0-9a-fA-F-]{36}$").matches(challengeId))
        require(Regex("^[A-Za-z0-9_-]{43}$").matches(nonceBase64Url))
        require(Regex("^[0-9a-fA-F-]{36}$").matches(requestId))
        require(decision == "approve" || decision == "reject")
        val reasonHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest((reason ?: "").toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val payload = listOf(
            "NEWEIX-SUPREME-CONTROL-DECISION-V1",
            challengeId,
            nonceBase64Url,
            requestId,
            decision,
            reasonHash,
        ).joinToString("\\n").toByteArray(StandardCharsets.UTF_8)

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            ?: throw IllegalStateException("The registered Supreme device signing key is unavailable. Re-register this device.")
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(payload)
        return Base64.getEncoder().encodeToString(signer.sign())
    }

    /** Removes the local attestation key when a device registration is reset. */
    @Synchronized
    fun delete() {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
            deleteEntry(KEY_ALIAS)
        }
    }
}
