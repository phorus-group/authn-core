package group.phorus.authn.core.services.impl

import com.google.gson.Gson
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import group.phorus.authn.core.config.IdpConfig
import io.jsonwebtoken.security.Jwks
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.net.http.HttpClient
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset

class JwksKeyLocatorTest {

    companion object {
        private lateinit var wireMock: WireMockServer

        private val ecKeyPair1 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        private val ecKeyPair2 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        private const val KID_1 = "key-1"
        private const val KID_2 = "key-2"
        private const val JWKS_PATH = "/.well-known/jwks.json"

        @JvmStatic
        @BeforeAll
        fun startWireMock() {
            wireMock = WireMockServer(
                WireMockConfiguration.wireMockConfig()
                    .dynamicPort()
                    .jettyAcceptors(1)
                    .containerThreads(10)
            )
            wireMock.start()
        }

        @JvmStatic
        @AfterAll
        fun stopWireMock() {
            wireMock.stop()
        }

        private fun jwksUri() = "http://localhost:${wireMock.port()}$JWKS_PATH"

        private fun buildConfig(
            jwkSetUri: String? = jwksUri(),
            cacheTtlMinutes: Long = 60,
        ) = IdpConfig(
            jwkSetUri = jwkSetUri,
            jwksCacheTtlMinutes = cacheTtlMinutes,
        )

        private val gson = Gson()

        private fun buildJwksJson(vararg kids: Pair<String, ECPublicKey>): String {
            val jwkMaps = kids.map { (kid, publicKey) ->
                Jwks.builder().key(publicKey).id(kid).build().toMap()
            }
            return gson.toJson(mapOf("keys" to jwkMaps))
        }

        private fun stubJwksEndpoint(responseBody: String, status: Int = 200) {
            wireMock.stubFor(
                WireMock.get(WireMock.urlEqualTo(JWKS_PATH))
                    .willReturn(
                        WireMock.aResponse()
                            .withStatus(status)
                            .withHeader(ContentTypeHeader.KEY, "application/json")
                            .withBody(responseBody)
                    )
            )
        }

        /** A clock a test moves by hand, so a cooldown or a TTL can pass without waiting for it. */
        private class TestClock(private var now: Instant = Instant.parse("2026-01-01T00:00:00Z")) : Clock() {
            override fun instant(): Instant = now
            override fun getZone(): ZoneId = ZoneOffset.UTC
            override fun withZone(zone: ZoneId): Clock = this

            fun advance(duration: Duration) {
                now = now.plus(duration)
            }
        }

        private fun mockJwsHeader(kid: String?): io.jsonwebtoken.JwsHeader {
            val header = mock<io.jsonwebtoken.JwsHeader>()
            whenever(header.keyId).thenReturn(kid)
            return header
        }
    }

    @BeforeEach
    fun resetStubs() {
        wireMock.resetAll()
    }

    @Nested
    @DisplayName("locate()")
    inner class Locate {

        @Test
        fun `throws SecurityException when kid header is missing`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val locator = JwksKeyLocator(buildConfig())

            val ex = assertThrows<SecurityException> { locator.locate(mockJwsHeader(null)) }
            assertTrue(ex.message!!.contains("kid"))
        }

        @Test
        fun `returns cached key without re-fetching`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val locator = JwksKeyLocator(buildConfig())

            val key1 = locator.locate(mockJwsHeader(KID_1))
            val key2 = locator.locate(mockJwsHeader(KID_1))

            assertEquals(key1, key2)
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `fetches JWKS on cache miss and returns key`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val locator = JwksKeyLocator(buildConfig())

            val key = locator.locate(mockJwsHeader(KID_1))

            assertNotNull(key)
            assertTrue(key is PublicKey)
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `fetches JWKS with multiple keys and resolves correct kid`() {
            stubJwksEndpoint(buildJwksJson(
                KID_1 to ecKeyPair1.public as ECPublicKey,
                KID_2 to ecKeyPair2.public as ECPublicKey,
            ))
            val locator = JwksKeyLocator(buildConfig())

            val key1 = locator.locate(mockJwsHeader(KID_1))
            val key2 = locator.locate(mockJwsHeader(KID_2))

            assertNotNull(key1)
            assertNotNull(key2)
            assertNotEquals(key1, key2)
        }

        @Test
        fun `throws SecurityException when kid is unknown after refresh`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val locator = JwksKeyLocator(buildConfig())

            val ex = assertThrows<SecurityException> { locator.locate(mockJwsHeader("unknown-kid")) }
            assertTrue(ex.message!!.contains("unknown-kid"))
        }
    }

    @Nested
    @DisplayName("forceRefresh()")
    inner class ForceRefresh {

        @Test
        fun `populates cache and keys are resolvable`() {
            stubJwksEndpoint(buildJwksJson(
                KID_1 to ecKeyPair1.public as ECPublicKey,
                KID_2 to ecKeyPair2.public as ECPublicKey,
            ))
            val locator = JwksKeyLocator(buildConfig())

            locator.forceRefresh()

            assertNotNull(locator.locate(mockJwsHeader(KID_1)))
            assertNotNull(locator.locate(mockJwsHeader(KID_2)))
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `replaces previous cache entries`() {
            stubJwksEndpoint(buildJwksJson(
                KID_1 to ecKeyPair1.public as ECPublicKey,
                KID_2 to ecKeyPair2.public as ECPublicKey,
            ))
            val locator = JwksKeyLocator(buildConfig())
            locator.forceRefresh()

            wireMock.resetAll()
            stubJwksEndpoint(buildJwksJson(KID_2 to ecKeyPair2.public as ECPublicKey))
            locator.forceRefresh()

            assertThrows<SecurityException> { locator.locate(mockJwsHeader(KID_1)) }
            assertNotNull(locator.locate(mockJwsHeader(KID_2)))
        }
    }

    @Nested
    @DisplayName("Cooldown and TTL")
    inner class CooldownAndTtl {

        @Test
        fun `re-fetches for an unknown kid once the cooldown has passed`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))

            wireMock.resetAll()
            stubJwksEndpoint(buildJwksJson(
                KID_1 to ecKeyPair1.public as ECPublicKey,
                KID_2 to ecKeyPair2.public as ECPublicKey,
            ))
            clock.advance(Duration.ofSeconds(31))

            assertNotNull(locator.locate(mockJwsHeader(KID_2)))
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `holds off a second fetch for an unknown kid inside the cooldown`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))
            clock.advance(Duration.ofSeconds(5))

            assertThrows<SecurityException> { locator.locate(mockJwsHeader("unknown-kid")) }
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `re-fetches a cached kid once the cache TTL has passed`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 60), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))
            clock.advance(Duration.ofMinutes(61))
            locator.locate(mockJwsHeader(KID_1))

            wireMock.verify(2, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `serves a cached kid within the TTL without re-fetching`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 60), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))
            clock.advance(Duration.ofMinutes(59))
            locator.locate(mockJwsHeader(KID_1))

            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `serves a stale cached kid when the refresh fails`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 60), HttpClient.newHttpClient(), clock)

            val fresh = locator.locate(mockJwsHeader(KID_1))

            wireMock.resetAll()
            stubJwksEndpoint("", status = 500)
            clock.advance(Duration.ofMinutes(61))

            assertEquals(fresh, locator.locate(mockJwsHeader(KID_1)))
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `an unknown kid throws the fetch failure when the refresh fails`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 60), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))

            wireMock.resetAll()
            stubJwksEndpoint("", status = 500)
            clock.advance(Duration.ofSeconds(31))

            val ex = assertThrows<SecurityException> { locator.locate(mockJwsHeader(KID_2)) }
            assertTrue(ex.message!!.contains("Failed to fetch JWKS"), "was: ${ex.message}")
        }

        @Test
        fun `a failing endpoint is left alone until the cooldown passes`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 60), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))

            wireMock.resetAll()
            stubJwksEndpoint("", status = 500)
            clock.advance(Duration.ofMinutes(61))

            locator.locate(mockJwsHeader(KID_1))
            clock.advance(Duration.ofSeconds(5))
            locator.locate(mockJwsHeader(KID_1))

            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }

        @Test
        fun `serves an expired cached kid while the cooldown holds`() {
            stubJwksEndpoint(buildJwksJson(KID_1 to ecKeyPair1.public as ECPublicKey))
            val clock = TestClock()
            val locator = JwksKeyLocator(buildConfig(cacheTtlMinutes = 0), HttpClient.newHttpClient(), clock)

            locator.locate(mockJwsHeader(KID_1))
            clock.advance(Duration.ofSeconds(5))

            assertNotNull(locator.locate(mockJwsHeader(KID_1)))
            wireMock.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo(JWKS_PATH)))
        }
    }

    @Nested
    @DisplayName("Error handling")
    inner class ErrorHandling {

        @Test
        fun `throws IllegalStateException when jwkSetUri is not configured`() {
            val locator = JwksKeyLocator(buildConfig(jwkSetUri = null))

            val ex = assertThrows<IllegalStateException> { locator.forceRefresh() }
            assertTrue(ex.message!!.contains("jwk-set-uri"))
        }

        @Test
        fun `throws SecurityException on HTTP fetch failure`() {
            stubJwksEndpoint("", status = 500)
            val locator = JwksKeyLocator(buildConfig())

            val ex = assertThrows<SecurityException> { locator.forceRefresh() }
            assertTrue(ex.message!!.contains("Failed to fetch JWKS"))
        }

        @Test
        fun `throws SecurityException on invalid JWKS JSON`() {
            stubJwksEndpoint("not-valid-json")
            val locator = JwksKeyLocator(buildConfig())

            val ex = assertThrows<SecurityException> { locator.forceRefresh() }
            assertTrue(ex.message!!.contains("Failed to parse JWKS"))
        }

        @Test
        fun `skips JWK entries without kid`() {
            val jwkWithoutKid = Jwks.builder()
                .key(ecKeyPair1.public as ECPublicKey)
                .build().toMap()
            val jwkWithKid = Jwks.builder()
                .key(ecKeyPair2.public as ECPublicKey)
                .id(KID_2)
                .build().toMap()

            stubJwksEndpoint(gson.toJson(mapOf("keys" to listOf(jwkWithoutKid, jwkWithKid))))
            val locator = JwksKeyLocator(buildConfig())

            locator.forceRefresh()

            assertNotNull(locator.locate(mockJwsHeader(KID_2)))
            assertThrows<SecurityException> { locator.locate(mockJwsHeader("nonexistent")) }
        }
    }
}
