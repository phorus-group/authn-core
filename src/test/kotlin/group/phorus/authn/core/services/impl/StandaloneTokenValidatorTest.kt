package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.*
import group.phorus.authn.core.dtos.TokenType
import group.phorus.authn.core.services.Validator
import group.phorus.exception.core.Unauthorized
import io.jsonwebtoken.Claims
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.*

/**
 * Unit tests for multi-format token creation and parsing.
 *
 * Tests all three token formats (JWS, JWE, nested-JWE) using the same
 * assertion logic to ensure consistent behavior across formats.
 */
class StandaloneTokenValidatorTest {

    companion object {
        // EC P-384 encryption keys
        private const val ENC_PRIVATE_KEY =
            "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCpoZWkEK8LcF2uGOI0abCj/ApvnAJeGPf+yMph+wfedOqhHbclczvNRdagjm0I2RmgBwYFK4EEACKhZANiAAReX6HMEPcJ05T5YCQeSPtz5kNPOlR44cBbZMOXrUwJ1JuyfobpbaJJ9fpW9paoWEy4yNIeYH4T/aplbIktIvTGo41ndJskCtSj26lsGi2llVArDQNttHH4jSyueKVyzBA="
        private const val ENC_PUBLIC_KEY =
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXl+hzBD3CdOU+WAkHkj7c+ZDTzpUeOHAW2TDl61MCdSbsn6G6W2iSfX6VvaWqFhMuMjSHmB+E/2qZWyJLSL0xqONZ3SbJArUo9upbBotpZVQKw0DbbRx+I0srnilcswQ"

        // EC P-384 signing keys
        private const val SIG_PRIVATE_KEY =
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCFB8ZviusbeTHR/iqQqS+rwbVhAWg/+oZ2gFjJ2yQRwNg9mH5MHexS06oTTjncWaihZANiAASktw4raXCAg6DL/7p0ypZKnGhpzBtXKWbndB2alBcZtykvNO+nOCyf2PVua14ppyFgZQC3V+TwQ1uTgOXf34SgTYj+qgkRzRuQfBFEgozMKqxUBQx0SmRZUpnv5AhmK6E="
        private const val SIG_PUBLIC_KEY =
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEpLcOK2lwgIOgy/+6dMqWSpxoacwbVylm53QdmpQXGbcpLzTvpzgsn9j1bmteKachYGUAt1fk8ENbk4Dl39+EoE2I/qoJEc0bkHwRRIKMzCqsVAUMdEpkWVKZ7+QIZiuh"

        private const val ISSUER = "phorus.group"
        private val TEST_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001")

        private fun buildConfig(format: TokenFormat): AuthNConfig = AuthNConfig(
            mode = AuthMode.STANDALONE,
            jwt = JwtConfig(
                issuer = ISSUER,
                tokenFormat = format,
                signing = SigningConfig(
                    algorithm = "EC",
                    encodedPrivateKey = SIG_PRIVATE_KEY,
                    encodedPublicKey = SIG_PUBLIC_KEY,
                ),
                encryption = EncryptionConfig(
                    algorithm = "EC",
                    keyAlgorithm = "ECDH-ES+A256KW",
                    aeadAlgorithm = "A192CBC-HS384",
                    encodedPublicKey = ENC_PUBLIC_KEY,
                    encodedPrivateKey = ENC_PRIVATE_KEY,
                ),
                expiration = ExpirationConfig(
                    tokenMinutes = 525_9600,       // ~10 years
                    refreshTokenMinutes = 525_9600, // ~10 years
                ),
            ),
        )
    }

    @Nested
    @DisplayName("JWS format")
    inner class JwsFormatTests {
        private val config = buildConfig(TokenFormat.JWS)
        private val factory = TokenCreator(config)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `access token round-trip`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin", "read"))
            val token = accessToken.token

            // JWS has 3 segments
            assertEquals(3, token.count { it == '.' } + 1, "JWS must have 3 Base64url segments")

            val authData = authenticator.authenticate(token)
            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.ACCESS_TOKEN, authData.tokenType)
            assertEquals(listOf("admin", "read"), authData.privileges)
            assertNotNull(authData.jti)
        }

        @Test
        fun `refresh token round-trip`() = runBlocking {
            val token = factory.createRefreshToken(TEST_USER_ID, expires = true)

            assertEquals(3, token.count { it == '.' } + 1)

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
        }

        @Test
        fun `non-expiring refresh token`() = runBlocking {
            val token = factory.createRefreshToken(TEST_USER_ID, expires = false)
            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
        }

        @Test
        fun `custom properties are preserved`() = runBlocking {
            val props = mapOf("deviceId" to "phone1", "region" to "eu-west")
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin"), props)
            val authData = authenticator.authenticate(accessToken.token)

            assertEquals("phone1", authData.properties["deviceId"])
            assertEquals("eu-west", authData.properties["region"])
        }

        @Test
        fun `properties include all standard JWT claims for validator access`() = runBlocking {
            val props = mapOf("customClaim" to "customValue")
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("read", "write"), props)
            val authData = authenticator.authenticate(accessToken.token)

            // Standard claims should be accessible to validators
            assertNotNull(authData.properties[Claims.ID])
            assertNotNull(authData.properties[Claims.SUBJECT])
            assertNotNull(authData.properties[Claims.ISSUER])
            assertNotNull(authData.properties[Claims.ISSUED_AT])
            assertNotNull(authData.properties[Claims.EXPIRATION])
            assertNotNull(authData.properties["scope"])

            // Custom claims should also be present
            assertEquals("customValue", authData.properties["customClaim"])
        }

        @Test
        fun `parseSignedClaims returns valid Jws`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin"))
            val jws = authenticator.parseSignedClaims(accessToken.token)

            assertEquals(TEST_USER_ID.toString(), jws.payload.subject)
            assertEquals(ISSUER, jws.payload.issuer)
        }
    }

    @Nested
    @DisplayName("JWE format")
    inner class JweFormatTests {
        private val config = buildConfig(TokenFormat.JWE)
        private val factory = TokenCreator(config)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `access token round-trip`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin", "read"))
            val token = accessToken.token

            // JWE has 5 segments
            assertEquals(5, token.count { it == '.' } + 1, "JWE must have 5 Base64url segments")

            val authData = authenticator.authenticate(token)
            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.ACCESS_TOKEN, authData.tokenType)
            assertEquals(listOf("admin", "read"), authData.privileges)
        }

        @Test
        fun `properties include all standard JWT claims for validator access`() = runBlocking {
            val props = mapOf("customClaim" to "customValue")
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("read", "write"), props)
            val authData = authenticator.authenticate(accessToken.token)

            // Standard claims should be accessible to validators
            assertNotNull(authData.properties[Claims.ID])
            assertNotNull(authData.properties[Claims.SUBJECT])
            assertNotNull(authData.properties[Claims.ISSUER])
            assertNotNull(authData.properties[Claims.ISSUED_AT])
            assertNotNull(authData.properties[Claims.EXPIRATION])
            assertNotNull(authData.properties["scope"])

            // Custom claims should also be present
            assertEquals("customValue", authData.properties["customClaim"])
        }

        @Test
        fun `refresh token round-trip`() = runBlocking {
            val token = factory.createRefreshToken(TEST_USER_ID, expires = true)

            assertEquals(5, token.count { it == '.' } + 1)

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
        }

        @Test
        fun `parseEncryptedClaims returns valid Jwe`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin"))
            val jwe = authenticator.parseEncryptedClaims(accessToken.token)

            assertEquals(TEST_USER_ID.toString(), jwe.payload.subject)
            assertEquals(ISSUER, jwe.payload.issuer)
        }
    }

    @Nested
    @DisplayName("Nested JWE format (sign-then-encrypt)")
    inner class NestedJweFormatTests {
        private val config = buildConfig(TokenFormat.NESTED_JWE)
        private val factory = TokenCreator(config)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `access token round-trip`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin", "read"))
            val token = accessToken.token

            // Nested JWE is still 5 segments (outer JWE)
            assertEquals(5, token.count { it == '.' } + 1, "Nested JWE must have 5 Base64url segments")

            val authData = authenticator.authenticate(token)
            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.ACCESS_TOKEN, authData.tokenType)
            assertEquals(listOf("admin", "read"), authData.privileges)
            assertNotNull(authData.jti)
        }

        @Test
        fun `refresh token round-trip`() = runBlocking {
            val token = factory.createRefreshToken(TEST_USER_ID, expires = true)
            val authData = authenticator.authenticate(token, enableValidators = false)

            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
        }

        @Test
        fun `custom properties are preserved`() = runBlocking {
            val props = mapOf("deviceId" to "phone1", "tokenThingy" to "true")
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin"), props)
            val authData = authenticator.authenticate(accessToken.token)

            assertEquals("phone1", authData.properties["deviceId"])
            assertEquals("true", authData.properties["tokenThingy"])
        }

        @Test
        fun `properties include all standard JWT claims for validator access`() = runBlocking {
            val props = mapOf("customClaim" to "customValue")
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("read", "write"), props)
            val authData = authenticator.authenticate(accessToken.token)

            // Standard claims should be accessible to validators
            assertNotNull(authData.properties[Claims.ID])
            assertNotNull(authData.properties[Claims.SUBJECT])
            assertNotNull(authData.properties[Claims.ISSUER])
            assertNotNull(authData.properties[Claims.ISSUED_AT])
            assertNotNull(authData.properties[Claims.EXPIRATION])
            assertNotNull(authData.properties["scope"])

            // Custom claims should also be present
            assertEquals("customValue", authData.properties["customClaim"])
        }

        @Test
        fun `nested JWE has cty JWT header`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("admin"))
            val token = accessToken.token

            // Peek at unencrypted JOSE header to verify cty
            val headerSegment = token.substringBefore('.')
            val headerJson = String(Base64.getUrlDecoder().decode(headerSegment))
            assertTrue(headerJson.contains("\"cty\""), "Nested JWE must have cty header")
            assertTrue(headerJson.contains("JWT"), "cty must be JWT")
        }
    }

    @Nested
    @DisplayName("Auto-detection: authenticator accepts tokens from any format")
    inner class CrossFormatTests {
        private val fullConfig = buildConfig(TokenFormat.NESTED_JWE)
        private val authenticator = StandaloneTokenValidator(fullConfig, emptyList())

        @Test
        fun `authenticator parses JWS token regardless of configured format`() = runBlocking {
            val jwsConfig = buildConfig(TokenFormat.JWS)
            val jwsFactory = TokenCreator(jwsConfig)
            val jwsToken = jwsFactory.createAccessToken(TEST_USER_ID, listOf("admin")).token

            // Authenticator configured for nested-JWE can still parse JWS
            val authData = authenticator.authenticate(jwsToken)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `authenticator parses plain JWE token regardless of configured format`() = runBlocking {
            val jweConfig = buildConfig(TokenFormat.JWE)
            val jweFactory = TokenCreator(jweConfig)
            val jweToken = jweFactory.createAccessToken(TEST_USER_ID, listOf("admin")).token

            val authData = authenticator.authenticate(jweToken)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `authenticator parses nested JWE token regardless of configured format`() = runBlocking {
            val nestedConfig = buildConfig(TokenFormat.NESTED_JWE)
            val nestedFactory = TokenCreator(nestedConfig)
            val nestedToken = nestedFactory.createAccessToken(TEST_USER_ID, listOf("admin")).token

            val authData = authenticator.authenticate(nestedToken)
            assertEquals(TEST_USER_ID, authData.userId)
        }
    }

    @Nested
    @DisplayName("Validator integration")
    inner class ValidatorTests {
        @Test
        fun `validators are invoked and can reject tokens`(): Unit = runBlocking {
            val config = buildConfig(TokenFormat.JWS)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "deviceId"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }

            val factory = TokenCreator(config)
            val authenticator = StandaloneTokenValidator(config, listOf(rejectingValidator))

            val token = factory.createAccessToken(
                TEST_USER_ID, listOf("admin"), mapOf("deviceId" to "phone1")
            ).token

            assertThrows<Unauthorized> {
                authenticator.authenticate(token)
            }
        }

        @Test
        fun `validators are skipped when enableValidators is false`() = runBlocking {
            val config = buildConfig(TokenFormat.JWS)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "deviceId"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }

            val factory = TokenCreator(config)
            val authenticator = StandaloneTokenValidator(config, listOf(rejectingValidator))

            val token = factory.createAccessToken(
                TEST_USER_ID, listOf("admin"), mapOf("deviceId" to "phone1")
            ).token

            // Should not throw when validators are disabled
            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
        }
    }

    @Nested
    @DisplayName("Error handling")
    inner class ErrorTests {
        private val config = buildConfig(TokenFormat.JWS)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `invalid token string throws Unauthorized`() {
            assertThrows<Unauthorized> {
                authenticator.authenticate("not-a-valid-token")
            }
        }

        @Test
        fun `tampered JWS token throws Unauthorized`(): Unit = runBlocking {
            val factory = TokenCreator(config)
            val token = factory.createAccessToken(TEST_USER_ID, listOf("admin")).token

            // Tamper with the signature (last segment)
            val tampered = token.dropLast(5) + "XXXXX"

            assertThrows<Unauthorized> {
                authenticator.authenticate(tampered)
            }
        }
    }
}
