package com.neweix.supreme.auth

/** Keeps a successfully rotated credential when a later server step may have committed. */
internal object SupremeSessionFailurePolicy {
    fun shouldRetainRefreshToken(rotatedTokenPersisted: Boolean, statusCode: Int?): Boolean =
        statusCode == 403 || (rotatedTokenPersisted && (statusCode == null || statusCode >= 500))

    /** Authentication failures require the interactive password + TOTP recovery screen. */
    fun shouldReturnToSignIn(statusCode: Int?): Boolean =
        statusCode == 400 || statusCode == 401 || statusCode == 403 || statusCode == 422
}