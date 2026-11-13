package com.neweix.supreme.auth

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SupremeSessionFailurePolicyTest {
    @Test
    fun retainsRotatedTokenAfterServerOrTransportFailure() {
        assertTrue(SupremeSessionFailurePolicy.shouldRetainRefreshToken(true, 500))
        assertTrue(SupremeSessionFailurePolicy.shouldRetainRefreshToken(true, 503))
        assertTrue(SupremeSessionFailurePolicy.shouldRetainRefreshToken(true, null))
    }

    @Test
    fun retainsExistingForbiddenRecoveryBehavior() {
        assertTrue(SupremeSessionFailurePolicy.shouldRetainRefreshToken(false, 403))
    }

    @Test
    fun clearsForUnauthorizedOrPrePersistenceFailures() {
        assertFalse(SupremeSessionFailurePolicy.shouldRetainRefreshToken(true, 401))
        assertFalse(SupremeSessionFailurePolicy.shouldRetainRefreshToken(true, 400))
        assertFalse(SupremeSessionFailurePolicy.shouldRetainRefreshToken(false, 500))
        assertFalse(SupremeSessionFailurePolicy.shouldRetainRefreshToken(false, null))
    }
}
