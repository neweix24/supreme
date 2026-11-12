package com.neweix.supreme.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SupremeRequestSigningKeyTest {
    @Test
    fun acceptsCanonicalRegistryTargets() {
        assertEquals(
            "/functions/v1/supreme-registry-api/v1/services?limit=50",
            SupremeRequestSigningKey.canonicalTarget(
                "/functions/v1/supreme-registry-api/v1/services?limit=50",
            ),
        )
        assertEquals(
            "/v1/services?limit=50&cursor=alpha",
            SupremeRequestSigningKey.canonicalTarget("/v1/services?limit=50&cursor=alpha"),
        )
    }

    @Test
    fun rejectsAbsoluteOrAuthorityTargets() {
        assertThrows(IllegalArgumentException::class.java) {
            SupremeRequestSigningKey.canonicalTarget("https://example.com/v1/services")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SupremeRequestSigningKey.canonicalTarget("//example.com/v1/services")
        }
    }

    @Test
    fun rejectsDotSegmentsAndEncodedSeparators() {
        listOf(
            "/v1/../admin",
            "/v1/%2E%2E/admin",
            "/v1%2Fadmin",
            "/v1%5Cadmin",
        ).forEach { target ->
            assertThrows(IllegalArgumentException::class.java) {
                SupremeRequestSigningKey.canonicalTarget(target)
            }
        }
    }

    @Test
    fun rejectsFragmentsMalformedEscapesAndDuplicateQueryKeys() {
        listOf(
            "/v1/services#fragment",
            "/v1/services?limit=1&limit=2",
            "/v1/services?x=%2f",
            "/v1/services?x=%GG",
        ).forEach { target ->
            assertThrows(IllegalArgumentException::class.java) {
                SupremeRequestSigningKey.canonicalTarget(target)
            }
        }
    }
}
