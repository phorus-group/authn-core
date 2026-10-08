package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.*
import group.phorus.authn.core.dtos.AccessToken
import group.phorus.authn.core.dtos.ExtraClaims
import group.phorus.authn.core.dtos.TokenType
import group.phorus.authn.core.services.Validator
import group.phorus.exception.core.Unauthorized
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
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

        private fun buildConfig(
            format: TokenFormat,
            claims: ClaimsMapping = ClaimsMapping(),
            issuer: String? = ISSUER,
            audience: String? = null,
            requireAudience: Boolean = false,
            requireIssuer: Boolean = false,
            clockSkewSeconds: Long = 0,
            tokenMinutes: Long = 10,
        ): AuthNConfig = AuthNConfig(
            mode = AuthMode.STANDALONE,
            jwt = JwtConfig(
                claims = claims,
                issuer = issuer,
                tokenFormat = format,
                audience = audience,
                requireAudience = requireAudience,
                requireIssuer = requireIssuer,
                clockSkewSeconds = clockSkewSeconds,
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
                expiration = ExpirationConfig(tokenMinutes = tokenMinutes),
            ),
        )

        /** The value the library writes into the [ExtraClaims.TYPE] header for a given type. */
        private fun typeHeaderValue(type: TokenType): String = type.mediaType

        private fun signingPrivateKey() = KeyFactory.getInstance("EC")
            .generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(SIG_PRIVATE_KEY)))

        private fun encryptionPublicKey() = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(ENC_PUBLIC_KEY)))

        /**
         * Signs an arbitrary claim set with [SIG_PRIVATE_KEY], so a test can hand the validator any
         * claim shape an issuer might send.
         */
        private fun signedTokenWith(claims: Map<String, Any>): String =
            signedTokenWith(claims, typeHeaderValue(TokenType.ACCESS_TOKEN))

        private fun signedTokenWith(claims: Map<String, Any>, typeHeader: String): String =
            Jwts.builder()
                .header()
                    .add(ExtraClaims.TYPE, typeHeader)
                .and()
                .claims()
                    .add(mapOf("sub" to TEST_USER_ID.toString(), "jti" to UUID.randomUUID().toString()))
                    .add(claims)
                .and()
                .signWith(signingPrivateKey())
                .compact()

        /**
         * Builds a nested JWE whose outer and inner headers claim different token types, which is the
         * only token that shows which of the two the validator trusts.
         */
        private fun nestedJweWithHeaders(inner: TokenType, outer: TokenType): String {
            val innerJws = signedTokenWith(emptyMap(), typeHeaderValue(inner))

            return Jwts.builder()
                .header()
                    .contentType("JWT")
                    .add(ExtraClaims.TYPE, typeHeaderValue(outer))
                .and()
                .content(innerJws.toByteArray(Charsets.UTF_8))
                .encryptWith(encryptionPublicKey(), Jwts.KEY.ECDH_ES_A256KW, Jwts.ENC.A192CBC_HS384)
                .compact()
        }

        /** The decoded JOSE header of the first segment of [token]. */
        private fun headerJson(token: String): String =
            Base64.getUrlDecoder().decode(token.substringBefore('.')).toString(Charsets.UTF_8)
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
            assertEquals(listOf("admin", "read"), authData.scope)
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
            assertEquals(listOf("admin", "read"), authData.scope)
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
            assertEquals(listOf("admin", "read"), authData.scope)
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
    @DisplayName("Audience, issuer and clock skew")
    inner class RegisteredClaimValidationTests {
        private val audienceConfig = buildConfig(
            TokenFormat.JWS,
            audience = "orders-service",
            requireAudience = true,
        )

        @Test
        fun `the audience is written when configured`(): Unit = runBlocking {
            val config = buildConfig(TokenFormat.JWS, audience = "orders-service")
            val token = TokenCreator(config).createAccessToken(TEST_USER_ID, listOf("openid")).token

            val claims = StandaloneTokenValidator(config, emptyList())
                .authenticate(token, enableValidators = false).properties

            // RFC 7519 SS4.1.3 allows aud to hold one value or an array, and JJWT parses either into a Set
            assertEquals(setOf("orders-service"), claims["aud"])
        }

        @Test
        fun `no audience claim is written when none is configured`(): Unit = runBlocking {
            val config = buildConfig(TokenFormat.JWS)
            val token = TokenCreator(config).createAccessToken(TEST_USER_ID, listOf("openid")).token

            val claims = StandaloneTokenValidator(config, emptyList())
                .authenticate(token, enableValidators = false).properties

            assertFalse(claims.containsKey("aud"))
        }

        @Test
        fun `a token issued for another audience is refused`() {
            val token = signedTokenWith(mapOf("aud" to "billing-service"))

            val ex = assertThrows<Unauthorized> {
                StandaloneTokenValidator(audienceConfig, emptyList())
                    .authenticate(token, enableValidators = false)
            }
            assertTrue(ex.message!!.contains("aud"), "was: ${ex.message}")
        }

        @Test
        fun `a token with no audience is refused when an audience is required`() {
            val ex = assertThrows<Unauthorized> {
                StandaloneTokenValidator(audienceConfig, emptyList())
                    .authenticate(signedTokenWith(emptyMap()), enableValidators = false)
            }
            assertTrue(ex.message!!.contains("aud"), "was: ${ex.message}")
        }

        @Test
        fun `the right audience is accepted`() {
            val token = signedTokenWith(mapOf("aud" to "orders-service"))

            val authData = StandaloneTokenValidator(audienceConfig, emptyList())
                .authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `a token from another issuer is refused when the issuer is required`() {
            val config = buildConfig(TokenFormat.JWS, requireIssuer = true)
            val token = signedTokenWith(mapOf("iss" to "someone-else"))

            val ex = assertThrows<Unauthorized> {
                StandaloneTokenValidator(config, emptyList()).authenticate(token, enableValidators = false)
            }
            assertTrue(ex.message!!.contains("iss"), "was: ${ex.message}")
        }

        @Test
        fun `a token with no issuer is refused when the issuer is required`() {
            val config = buildConfig(TokenFormat.JWS, requireIssuer = true)

            val ex = assertThrows<Unauthorized> {
                StandaloneTokenValidator(config, emptyList())
                    .authenticate(signedTokenWith(emptyMap()), enableValidators = false)
            }
            assertTrue(ex.message!!.contains("iss"), "was: ${ex.message}")
        }

        @Test
        fun `the configured issuer is accepted`() {
            val config = buildConfig(TokenFormat.JWS, requireIssuer = true)
            val token = signedTokenWith(mapOf("iss" to ISSUER))

            val authData = StandaloneTokenValidator(config, emptyList())
                .authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `another issuer is accepted while the issuer is not required`() {
            val config = buildConfig(TokenFormat.JWS)
            val token = signedTokenWith(mapOf("iss" to "someone-else"))

            val authData = StandaloneTokenValidator(config, emptyList())
                .authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `a token expired inside the clock skew is accepted`(): Unit = runBlocking {
            val minting = buildConfig(TokenFormat.JWS, tokenMinutes = -1)
            val token = TokenCreator(minting).createAccessToken(TEST_USER_ID, listOf("openid")).token

            val validating = buildConfig(TokenFormat.JWS, clockSkewSeconds = 300)

            val authData = StandaloneTokenValidator(validating, emptyList())
                .authenticate(token, enableValidators = false)
            assertEquals(TEST_USER_ID, authData.userId)
        }

        @Test
        fun `a token expired beyond the clock skew is refused`(): Unit = runBlocking {
            val minting = buildConfig(TokenFormat.JWS, tokenMinutes = -10)
            val token = TokenCreator(minting).createAccessToken(TEST_USER_ID, listOf("openid")).token

            val validating = buildConfig(TokenFormat.JWS, clockSkewSeconds = 60)

            assertThrows<Unauthorized> {
                StandaloneTokenValidator(validating, emptyList())
                    .authenticate(token, enableValidators = false)
            }
        }

        @Test
        fun `an expired token is refused when no skew is allowed`(): Unit = runBlocking {
            val minting = buildConfig(TokenFormat.JWS, tokenMinutes = -1)
            val token = TokenCreator(minting).createAccessToken(TEST_USER_ID, listOf("openid")).token

            assertThrows<Unauthorized> {
                StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())
                    .authenticate(token, enableValidators = false)
            }
        }

        @Test
        fun `requiring an audience without configuring one is refused at construction`() {
            val config = buildConfig(TokenFormat.JWS, requireAudience = true)

            assertThrows<IllegalArgumentException> { StandaloneTokenValidator(config, emptyList()) }
        }

        @Test
        fun `requiring an issuer without configuring one is refused at construction`() {
            val config = buildConfig(TokenFormat.JWS, issuer = null, requireIssuer = true)

            assertThrows<IllegalArgumentException> { StandaloneTokenValidator(config, emptyList()) }
        }
    }

    @Nested
    @DisplayName("The typ header")
    inner class TypeHeaderTests {
        private val config = buildConfig(TokenFormat.JWS)
        private val factory = TokenCreator(config)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `an access token header carries the RFC 9068 media type`(): Unit = runBlocking {
            val token = factory.createAccessToken(TEST_USER_ID, listOf("openid")).token

            assertTrue(
                headerJson(token).contains(""""typ":"at+jwt""""),
                "header was: ${headerJson(token)}",
            )
        }

        @Test
        fun `a refresh token header carries the refresh media type`(): Unit = runBlocking {
            val token = factory.createRefreshToken(TEST_USER_ID, expires = true)

            assertTrue(
                headerJson(token).contains(""""typ":"rt+jwt""""),
                "header was: ${headerJson(token)}",
            )
        }

        @Test
        fun `a media type the library does not know throws Unauthorized`() {
            val token = signedTokenWith(emptyMap(), "application/octet-stream")

            assertThrows<Unauthorized> { authenticator.authenticate(token, enableValidators = false) }
        }

        @Test
        fun `the media type is matched without regard to case`() {
            val token = signedTokenWith(emptyMap(), typeHeaderValue(TokenType.ACCESS_TOKEN).uppercase())

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(TokenType.ACCESS_TOKEN, authData.tokenType)
        }

        @Test
        fun `the inner signed header decides the token type`() {
            val nestedConfig = buildConfig(TokenFormat.NESTED_JWE)
            val nestedAuthenticator = StandaloneTokenValidator(nestedConfig, emptyList())

            val token = nestedJweWithHeaders(
                inner = TokenType.REFRESH_TOKEN,
                outer = TokenType.ACCESS_TOKEN,
            )

            val authData = nestedAuthenticator.authenticate(token, enableValidators = false)
            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
        }
    }

    @Nested
    @DisplayName("Claim mapping: roles and scope are read separately")
    inner class ClaimMappingTests {

        @Test
        fun `roles claim holding a JSON array is read into roles`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf(
                "roles" to listOf("ADMIN@organization:9b1c", "VIEWER@organization:7a21"),
            ))

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(
                listOf("ADMIN@organization:9b1c", "VIEWER@organization:7a21"),
                authData.roles,
            )
        }

        @Test
        fun `scope claim holding a JSON array is read into scope`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf("scope" to listOf("bit:read", "bit:create")))

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(listOf("bit:read", "bit:create"), authData.scope)
        }

        @Test
        fun `roles and scope are both read from the same token and stay separate`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf(
                "roles" to listOf("ADMIN@organization:9b1c"),
                "scope" to "openid profile",
            ))

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(listOf("ADMIN@organization:9b1c"), authData.roles)
            assertEquals(listOf("openid", "profile"), authData.scope)
        }

        @Test
        fun `configured claim names replace the registered defaults`() {
            val config = buildConfig(
                TokenFormat.JWS,
                claims = ClaimsMapping(scope = "scp", roles = "entitlements"),
            )
            val authenticator = StandaloneTokenValidator(config, emptyList())

            val token = signedTokenWith(mapOf(
                "scp" to "bit:read bit:create",
                "entitlements" to listOf("ADMIN", "VIEWER"),
            ))

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(listOf("ADMIN", "VIEWER"), authData.roles)
            assertEquals(listOf("bit:read", "bit:create"), authData.scope)
        }

        @Test
        fun `blank entries in a space-delimited claim are dropped`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf("scope" to "  bit:read   bit:create "))

            val authData = authenticator.authenticate(token, enableValidators = false)
            assertEquals(listOf("bit:read", "bit:create"), authData.scope)
        }

        @Test
        fun `a missing claim yields an empty list`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val authData = authenticator.authenticate(signedTokenWith(emptyMap()), enableValidators = false)

            assertEquals(emptyList<String>(), authData.roles)
            assertEquals(emptyList<String>(), authData.scope)
        }
    }

    @Nested
    @DisplayName("Minting with a claims map")
    inner class ClaimsMapMintTests {
        private val config = buildConfig(TokenFormat.JWS)
        private val factory = TokenCreator(config)
        private val authenticator = StandaloneTokenValidator(config, emptyList())

        @Test
        fun `a list claim is written as a JSON array and read back as a list`(): Unit = runBlocking {
            val entries = listOf("ADMIN@organization:9b1c", "VIEWER@organization:7a21")

            val accessToken = factory.createAccessToken(TEST_USER_ID, mapOf("roles" to entries))
            val authData = authenticator.authenticate(accessToken.token, enableValidators = false)

            assertEquals(entries, authData.roles)
            assertInstanceOf(List::class.java, authData.properties["roles"])
        }

        @Test
        fun `the returned AccessToken reports the authority the token carries`() = runBlocking {
            val accessToken = factory.createAccessToken(
                TEST_USER_ID,
                mapOf("roles" to listOf("ADMIN@organization:9b1c"), "scope" to "openid profile"),
            )

            assertEquals(listOf("ADMIN@organization:9b1c"), accessToken.roles)
            assertEquals(listOf("openid", "profile"), accessToken.scope)
        }

        @Test
        fun `a nested object claim survives the round trip`(): Unit = runBlocking {
            val accessToken = factory.createAccessToken(
                TEST_USER_ID,
                mapOf("realm_access" to mapOf("roles" to listOf("ADMIN"))),
            )
            val authData = authenticator.authenticate(accessToken.token, enableValidators = false)

            val realmAccess = assertInstanceOf(Map::class.java, authData.properties["realm_access"])
            assertEquals(listOf("ADMIN"), realmAccess["roles"])
        }

        @Test
        fun `a refresh token carries its claims map`(): Unit = runBlocking {
            val token = factory.createRefreshToken(
                TEST_USER_ID,
                mapOf("deviceEpoch" to listOf("a", "b")),
                expires = true,
            )
            val authData = authenticator.authenticate(token, enableValidators = false)

            assertEquals(TokenType.REFRESH_TOKEN, authData.tokenType)
            assertInstanceOf(List::class.java, authData.properties["deviceEpoch"])
        }

        @Test
        fun `each registered claim name is rejected by name`() {
            listOf("jti", "sub", "iss", "iat", "exp", "nbf", "aud").forEach { reserved ->
                val ex = assertThrows<IllegalArgumentException> {
                    runBlocking { factory.createAccessToken(TEST_USER_ID, mapOf(reserved to "anything")) }
                }
                assertTrue(
                    ex.message!!.contains(reserved),
                    "the message must name the offending key, was: ${ex.message}",
                )
            }
        }

        @Test
        fun `a registered claim name is rejected on the refresh path too`() {
            val ex = assertThrows<IllegalArgumentException> {
                runBlocking {
                    factory.createRefreshToken(TEST_USER_ID, mapOf("exp" to 1L), expires = true)
                }
            }
            assertTrue(ex.message!!.contains("exp"), "was: ${ex.message}")
        }

        @Test
        fun `a registered claim name is rejected on the properties path too`() {
            val ex = assertThrows<IllegalArgumentException> {
                runBlocking {
                    factory.createAccessToken(TEST_USER_ID, listOf("openid"), mapOf("sub" to "someone-else"))
                }
            }
            assertTrue(ex.message!!.contains("sub"), "was: ${ex.message}")
        }

        @Test
        fun `the subject stays the given user id`() = runBlocking {
            val accessToken = factory.createAccessToken(TEST_USER_ID, mapOf("roles" to listOf("ADMIN")))
            val authData = authenticator.authenticate(accessToken.token, enableValidators = false)

            assertEquals(TEST_USER_ID, authData.userId)
            assertEquals(ISSUER, authData.properties["iss"])
        }

        @Test
        fun `an unsupported implementation says which method to override`() {
            val bare = object : group.phorus.authn.core.services.TokenFactory {
                override suspend fun createAccessToken(
                    userId: UUID,
                    scope: List<String>,
                    properties: Map<String, String>,
                ) = AccessToken("")

                override suspend fun createRefreshToken(
                    userId: UUID,
                    expires: Boolean,
                    properties: Map<String, String>,
                ) = ""
            }

            val ex = assertThrows<UnsupportedOperationException> {
                runBlocking { bare.createAccessToken(TEST_USER_ID, mapOf("roles" to listOf("ADMIN"))) }
            }
            assertTrue(
                ex.message!!.contains("createAccessToken"),
                "was: ${ex.message}",
            )
        }
    }

    @Nested
    @DisplayName("Structured claim values")
    inner class StructuredClaimTests {

        @Test
        fun `a claim holding a JSON array arrives in properties as a list`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf("roles" to listOf("ADMIN", "VIEWER")))

            val properties = authenticator.authenticate(token, enableValidators = false).properties
            assertInstanceOf(List::class.java, properties["roles"])
            assertEquals(listOf("ADMIN", "VIEWER"), properties["roles"])
        }

        @Test
        fun `a nested object claim arrives in properties as a map`() {
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val token = signedTokenWith(mapOf(
                "realm_access" to mapOf("roles" to listOf("ADMIN")),
            ))

            val properties = authenticator.authenticate(token, enableValidators = false).properties
            val realmAccess = assertInstanceOf(Map::class.java, properties["realm_access"])
            assertEquals(listOf("ADMIN"), realmAccess["roles"])
        }

        @Test
        fun `a numeric date claim arrives as a count of seconds`(): Unit = runBlocking {
            val accessToken = TokenCreator(buildConfig(TokenFormat.JWS))
                .createAccessToken(TEST_USER_ID, listOf("openid"))
            val authenticator = StandaloneTokenValidator(buildConfig(TokenFormat.JWS), emptyList())

            val properties = authenticator.authenticate(accessToken.token, enableValidators = false).properties

            assertInstanceOf(java.lang.Long::class.java, properties[Claims.ISSUED_AT])
            assertInstanceOf(java.lang.Long::class.java, properties[Claims.EXPIRATION])
        }

        @Test
        fun `a validator is handed the claim value as the token carried it`() {
            val seen = mutableMapOf<String, Any?>()
            val capturingValidator = object : Validator {
                override fun accepts(property: String) = property == "roles"
                override fun isValid(value: Any?, properties: Map<String, Any?>): Boolean {
                    seen["value"] = value
                    seen["fromProperties"] = properties["roles"]
                    return true
                }
            }

            val authenticator = StandaloneTokenValidator(
                buildConfig(TokenFormat.JWS),
                listOf(capturingValidator),
            )

            authenticator.authenticate(signedTokenWith(mapOf("roles" to listOf("ADMIN", "VIEWER"))))

            assertInstanceOf(List::class.java, seen["value"])
            assertEquals(listOf("ADMIN", "VIEWER"), seen["value"])
            assertEquals(listOf("ADMIN", "VIEWER"), seen["fromProperties"])
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
                override fun isValid(value: Any?, properties: Map<String, Any?>) = false
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
                override fun isValid(value: Any?, properties: Map<String, Any?>) = false
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
