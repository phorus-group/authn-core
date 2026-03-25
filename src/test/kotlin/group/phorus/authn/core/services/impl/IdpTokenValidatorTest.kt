package group.phorus.authn.core.services.impl

import com.google.gson.Gson
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.http.ContentTypeHeader
import group.phorus.authn.core.config.*
import group.phorus.authn.core.services.Validator
import group.phorus.exception.core.Unauthorized
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Jwks
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.*

class IdpTokenValidatorTest {

    companion object {
        private lateinit var wireMock: WireMockServer

        private val signingKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()

        private val privateKey = signingKeyPair.private as ECPrivateKey
        private val publicKey = signingKeyPair.public as ECPublicKey

        private val encryptionKeyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        private val encryptionPublicKey = encryptionKeyPair.public as RSAPublicKey
        private val encryptionPrivateKey = encryptionKeyPair.private as RSAPrivateKey

        private const val ISSUER = "https://test-idp.example.com"
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

            val jwkMap = Jwks.builder().key(publicKey).id("test-key-1").build().toMap()
            val jwksJson = gson.toJson(mapOf("keys" to listOf(jwkMap)))

            wireMock.stubFor(
                WireMock.get(WireMock.urlEqualTo(JWKS_PATH))
                    .willReturn(
                        WireMock.aResponse()
                            .withStatus(200)
                            .withHeader(ContentTypeHeader.KEY, "application/json")
                            .withBody(jwksJson)
                    )
            )
        }

        @JvmStatic
        @AfterAll
        fun stopWireMock() {
            wireMock.stop()
        }

        private val gson = Gson()

        private fun jwksUri() = "http://localhost:${wireMock.port()}$JWKS_PATH"

        private fun createIdpToken(claims: Map<String, Any>, kid: String = "test-key-1"): String =
            Jwts.builder()
                .header().keyId(kid).and()
                .claims().add(claims).and()
                .signWith(privateKey)
                .compact()

        private fun createIdpJweToken(claims: Map<String, Any>): String =
            Jwts.builder()
                .claims().add(claims).and()
                .encryptWith(encryptionPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
                .compact()

        private fun createIdpNestedJweToken(claims: Map<String, Any>, kid: String = "test-key-1"): String {
            val innerJws = createIdpToken(claims, kid)

            return Jwts.builder()
                .header()
                    .contentType("JWT")
                .and()
                .content(innerJws.toByteArray(Charsets.UTF_8))
                .encryptWith(encryptionPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
                .compact()
        }

        private fun createKeyLocator(config: AuthNConfig): JwksKeyLocator {
            val locator = JwksKeyLocator(config.idp)
            locator.forceRefresh()
            return locator
        }

        private fun buildConfig(
            subjectClaim: String = "sub",
            privilegesClaim: String = "scope",
        ) = AuthNConfig(
            mode = AuthMode.IDP_DELEGATED,
            idp = IdpConfig(
                issuerUri = ISSUER,
                jwkSetUri = jwksUri(),
                claims = ClaimsMapping(
                    subject = subjectClaim,
                    privileges = privilegesClaim,
                ),
            ),
        )

        private fun buildEncryptedConfig(
            subjectClaim: String = "sub",
            privilegesClaim: String = "scope",
        ) = AuthNConfig(
            mode = AuthMode.IDP_DELEGATED,
            idp = IdpConfig(
                issuerUri = ISSUER,
                jwkSetUri = jwksUri(),
                claims = ClaimsMapping(
                    subject = subjectClaim,
                    privileges = privilegesClaim,
                ),
                encryption = IdpEncryptionConfig(
                    algorithm = "RSA",
                    encodedPrivateKey = Base64.getEncoder().encodeToString(
                        encryptionPrivateKey.encoded
                    ),
                ),
            ),
        )
    }

    @Nested
    @DisplayName("Auth0-style tokens")
    inner class Auth0StyleTests {
        @Test
        fun `extracts subject and permissions array`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "permissions")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "auth0|abc123def456",
                "permissions" to listOf("read:users", "write:users", "admin"),
            ))

            val authData = validator.authenticate(token)
            assertNotNull(authData.userId)
            assertEquals(listOf("read:users", "write:users", "admin"), authData.privileges)
        }

        @Test
        fun `extracts space-separated scope string`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scope")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "auth0|abc123",
                "scope" to "openid profile email read:users",
            ))

            val authData = validator.authenticate(token)
            assertEquals(listOf("openid", "profile", "email", "read:users"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Azure AD / Entra ID-style tokens")
    inner class AzureAdStyleTests {
        @Test
        fun `extracts oid as subject and roles array`() {
            val config = buildConfig(subjectClaim = "oid", privilegesClaim = "roles")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val oid = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "some-pairwise-id",
                "oid" to oid,
                "roles" to listOf("User.ReadWrite", "Application.Admin"),
                "scp" to "access_as_user",
            ))

            val authData = validator.authenticate(token)
            assertEquals(UUID.fromString(oid), authData.userId)
            assertEquals(listOf("User.ReadWrite", "Application.Admin"), authData.privileges)
        }

        @Test
        fun `extracts scp as space-separated string`() {
            val config = buildConfig(subjectClaim = "oid", privilegesClaim = "scp")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val oid = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to "some-pairwise-id",
                "oid" to oid,
                "scp" to "User.Read Mail.Send",
            ))

            val authData = validator.authenticate(token)
            assertEquals(listOf("User.Read", "Mail.Send"), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Keycloak-style tokens (nested claims)")
    inner class KeycloakStyleTests {
        @Test
        fun `extracts roles from nested realm_access path`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "realm_access.roles")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId,
                "realm_access" to mapOf("roles" to listOf("admin", "user", "manager")),
                "preferred_username" to "john.doe",
            ))

            val authData = validator.authenticate(token)
            assertEquals(UUID.fromString(userId), authData.userId)
            assertEquals(listOf("admin", "user", "manager"), authData.privileges)
        }

        @Test
        fun `returns empty list when nested path does not exist`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "realm_access.roles")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID().toString()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId,
            ))

            val authData = validator.authenticate(token)
            assertEquals(emptyList<String>(), authData.privileges)
        }
    }

    @Nested
    @DisplayName("Edge cases")
    inner class EdgeCaseTests {
        @Test
        fun `missing subject claim throws Unauthorized`() {
            val config = buildConfig(subjectClaim = "sub", privilegesClaim = "scope")
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> { validator.authenticate(token) }
        }

        @Test
        fun `expired token throws Unauthorized`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
                "iat" to Date.from(Instant.now().minusSeconds(7200)),
                "exp" to Date.from(Instant.now().minusSeconds(3600)),
            ))

            assertThrows<Unauthorized> { validator.authenticate(token) }
        }

        @Test
        fun `wrong issuer throws Unauthorized`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpToken(mapOf(
                "iss" to "https://wrong-issuer.example.com",
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> { validator.authenticate(token) }
        }

        @Test
        fun `UUID subject is used directly`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val uuid = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to uuid.toString(),
                "scope" to "openid",
            ))

            val authData = validator.authenticate(token)
            assertEquals(uuid, authData.userId)
        }

        @Test
        fun `non-UUID subject gets deterministic UUID conversion`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val subject = "auth0|abc123def456"
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to subject,
                "scope" to "openid",
            ))

            val authData = validator.authenticate(token)
            val expectedUuid = UUID.nameUUIDFromBytes(subject.toByteArray(Charsets.UTF_8))
            assertEquals(expectedUuid, authData.userId)

            val authData2 = validator.authenticate(token)
            assertEquals(authData.userId, authData2.userId)
        }
    }

    @Nested
    @DisplayName("JWE tokens (encrypted only)")
    inner class JweTokenTests {
        @Test
        fun `decrypts JWE token and extracts claims`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            val authData = validator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("read", "write"), authData.privileges)
        }

        @Test
        fun `JWE token without encryption config throws Unauthorized`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "openid",
            ))

            assertThrows<Unauthorized> { validator.authenticate(token) }
        }
    }

    @Nested
    @DisplayName("Nested JWE tokens (sign then encrypt)")
    inner class NestedJweTokenTests {
        @Test
        fun `decrypts and verifies nested JWE token`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write admin",
            ))

            val authData = validator.authenticate(token)
            assertEquals(userId, authData.userId)
            assertEquals(listOf("read", "write", "admin"), authData.privileges)
        }

        @Test
        fun `properties include all standard JWT claims for validator access`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpNestedJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "aud" to "test-audience",
                "scope" to "read write",
                "custom_claim" to "custom_value",
            ))

            val authData = validator.authenticate(token)

            assertNotNull(authData.properties[Claims.ISSUER])
            assertEquals(ISSUER, authData.properties[Claims.ISSUER])
            assertNotNull(authData.properties[Claims.SUBJECT])
            assertEquals("custom_value", authData.properties["custom_claim"])
        }
    }

    @Nested
    @DisplayName("Validator integration")
    inner class ValidatorTests {
        @Test
        fun `enableValidators false skips validator execution`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val validator = IdpTokenValidator(config, locator, listOf(rejectingValidator))

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            val authData = validator.authenticate(token, enableValidators = false)
            assertEquals(userId, authData.userId)
        }

        @Test
        fun `enableValidators true invokes validators`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val rejectingValidator = object : Validator {
                override fun accepts(property: String) = property == "scope"
                override fun isValid(value: String, properties: Map<String, String>) = false
            }
            val validator = IdpTokenValidator(config, locator, listOf(rejectingValidator))

            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to UUID.randomUUID().toString(),
                "scope" to "read write",
            ))

            assertThrows<Unauthorized> { validator.authenticate(token) }
        }
    }

    @Nested
    @DisplayName("Low-level parse methods")
    inner class ParseMethodTests {
        @Test
        fun `parseSignedClaims returns raw Jws object`() {
            val config = buildConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "read write",
            ))

            val jws = validator.parseSignedClaims(token)
            assertEquals(userId.toString(), jws.payload.subject)
            assertEquals(ISSUER, jws.payload.issuer)
        }

        @Test
        fun `parseEncryptedClaims returns raw Jwe object`() {
            val config = buildEncryptedConfig()
            val locator = createKeyLocator(config)
            val validator = IdpTokenValidator(config, locator)

            val userId = UUID.randomUUID()
            val token = createIdpJweToken(mapOf(
                "iss" to ISSUER,
                "sub" to userId.toString(),
                "scope" to "admin",
            ))

            val jwe = validator.parseEncryptedClaims(token)
            assertEquals(userId.toString(), jwe.payload.subject)
        }
    }
}
