package com.neweix.supreme.auth

/** Keeps a successfully rotated credential when a later server step may have committed. */
internal object SupremeSessionFailurePolicy {
    fun shouldRetainRefreshToken(rotatedTokenPersisted: Boolean, statusCode: Int?): Boolean =
        statusCode == 403 || (rotatedTokenPersisted && (statusCode == null || statusCode >= 500))
}
