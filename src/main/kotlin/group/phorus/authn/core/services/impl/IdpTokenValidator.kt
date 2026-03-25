package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.AuthNConfig
import group.phorus.authn.core.dtos.AuthData
import group.phorus.authn.core.dtos.TokenType
import group.phorus.authn.core.services.Authenticator
import group.phorus.authn.core.services.Validator
import group.phorus.exception.core.Unauthorized
import io.jsonwebtoken.*
import org.slf4j.LoggerFactory
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

/**
 * [Authenticator] implementation that validates tokens issued by an external Identity Provider (IdP).
 *
 * ### Supported token formats
 * The token format is auto-detected at parse time:
 *
 * | Format | Detection | Validation |
 * |--------|-----------|------------|
 * | **JWS** | 3 Base64url segments | Signature verification via the provided [keyLocator]. |
 * | **JWE** | 5 segments, no `cty: "JWT"` | Decryption using the configured `idp.encryption` private key. |
 * | **Nested JWE** | 5 segments, `cty: "JWT"` | Decryption, then inner JWS signature verification via [keyLocator]. |
 *
 * ### Claim extraction
 * - **Subject**: read from the claim named by [config.idp.claims.subject][group.phorus.authn.core.config.ClaimsMapping.subject] (default `sub`).
 * - **Privileges**: read from the claim named by [config.idp.claims.privileges][group.phorus.authn.core.config.ClaimsMapping.privileges] (default `scope`).
 *   Supports three value formats transparently:
 *   - Space-separated string (e.g. Auth0 `scope`, Azure AD `scp`)
 *   - JSON array of strings (e.g. Auth0 `permissions`, Okta `scp`, Azure AD `roles`)
 *   - Nested JSON path with dot notation (e.g. Keycloak `realm_access.roles`)
 *
 * ### IdP compatibility
 * | IdP | Subject config | Privileges config |
 * |-----|---------------|------------------|
 * | Auth0 | `sub` (default) | `permissions` or `scope` |
 * | Azure AD / Entra ID | `oid` | `scp` or `roles` |
 * | Google / Firebase | `sub` (default) | `scope` or custom |
 * | Keycloak | `sub` (default) | `realm_access.roles` |
 * | Okta | `sub` (default) | `scp` or `groups` |
 *
 * @param config The authentication configuration containing IdP settings.
 * @param keyLocator A JJWT [Locator] that resolves signing keys (e.g. [JwksKeyLocator]).
 * @param validators Optional list of [Validator] instances to run after claim extraction.
 * @see JwksKeyLocator
 * @see Validator
 */
class IdpTokenValidator(
    private val config: AuthNConfig,
    private val keyLocator: Locator<Key>,
    private val validators: List<Validator> = emptyList(),
) : Authenticator {

    private val log = LoggerFactory.getLogger(IdpTokenValidator::class.java)

    override fun authenticate(jwt: String, enableValidators: Boolean): AuthData {
        val enabledValidators = if (enableValidators) validators else emptyList()
        val claims = parseToken(jwt)

        val claimsMapping = config.idp.claims

        val subject = extractStringClaim(claims, claimsMapping.subject)
            ?: throw Unauthorized("IdP token is missing the '${claimsMapping.subject}' claim")

        val userId = runCatching { UUID.fromString(subject) }.getOrElse {
            UUID.nameUUIDFromBytes(subject.toByteArray(Charsets.UTF_8))
        }

        val privileges = extractPrivileges(claims, claimsMapping.privileges)

        val jti = claims.id ?: UUID.nameUUIDFromBytes(
            "$subject-${claims.issuedAt?.time ?: System.currentTimeMillis()}"
                .toByteArray(Charsets.UTF_8)
        ).toString()

        val properties = claims.mapNotNull { (key, value) ->
            key to value.toString()
        }.toMap().also { props ->
            props.forEach { (key, value) ->
                enabledValidators.filter { it.accepts(key) }.forEach { validator ->
                    if (!validator.isValid(value, props))
                        throw Unauthorized("IdP token validation failed")
                }
            }
        }

        return AuthData(
            userId = userId,
            tokenType = TokenType.ACCESS_TOKEN,
            jti = jti,
            privileges = privileges,
            properties = properties,
        )
    }

    override fun parseSignedClaims(jwt: String): Jws<Claims> = verifyJws(jwt)

    override fun parseEncryptedClaims(jwt: String): Jwe<Claims> = decryptJweClaims(jwt)

    private fun parseToken(jwt: String): Claims {
        val segmentCount = jwt.count { it == '.' } + 1

        return when (segmentCount) {
            3 -> verifyJws(jwt).payload
            5 -> {
                val isNested = peekJweContentType(jwt).equals("JWT", ignoreCase = true)
                if (isNested) parseNestedJwe(jwt) else decryptJweClaims(jwt).payload
            }
            else -> throw Unauthorized("Invalid IdP Token")
        }
    }

    private fun verifyJws(jwt: String): Jws<Claims> =
        runCatching {
            val parserBuilder = Jwts.parser()
                .keyLocator(keyLocator)

            config.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseSignedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    private fun decryptJweClaims(jwt: String): Jwe<Claims> =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()

            val parserBuilder = Jwts.parser()
                .decryptWith(privateKey)

            config.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseEncryptedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    private fun parseNestedJwe(jwt: String): Claims =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()

            val jwe = Jwts.parser()
                .decryptWith(privateKey)
                .build()
                .parseEncryptedContent(jwt)

            val innerJwsString = jwe.payload.toString(Charsets.UTF_8)

            val parserBuilder = Jwts.parser()
                .keyLocator(keyLocator)

            config.idp.issuerUri?.let { issuer ->
                parserBuilder.requireIssuer(issuer)
            }

            parserBuilder.build().parseSignedClaims(innerJwsString).payload
        }.getOrElse { handleParsingException(it) }

    private fun peekJweContentType(jwt: String): String? =
        runCatching {
            val headerSegment = jwt.substringBefore('.')
            val headerJson = Base64.getUrlDecoder().decode(headerSegment).toString(Charsets.UTF_8)
            val ctyRegex = """"cty"\s*:\s*"([^"]+)"""".toRegex()
            ctyRegex.find(headerJson)?.groupValues?.get(1)
        }.getOrNull()

    private fun resolveEncryptionPrivateKey(): PrivateKey {
        val enc = config.idp.encryption
        val encodedKey = enc.encodedPrivateKey
            ?: throw Unauthorized("IdP encryption private key is not configured but an encrypted IdP token was received")
        val keyBytes = Base64.getDecoder().decode(encodedKey)
        val keyFactory = KeyFactory.getInstance(enc.algorithm)
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    private fun <T> handleParsingException(it: Throwable): T {
        when (it) {
            is SecurityException,
            is IllegalArgumentException,
            is MalformedJwtException,
            is UnsupportedJwtException -> throw Unauthorized("Invalid IdP Token")
            is ExpiredJwtException -> throw Unauthorized("IdP Token expired")
            is IncorrectClaimException -> {
                log.warn("IdP token claim validation failed: {}", it.message)
                throw Unauthorized("IdP Token validation failed: ${it.claimName}")
            }
            is MissingClaimException -> {
                log.warn("IdP token missing required claim: {}", it.claimName)
                throw Unauthorized("IdP Token missing required claim: ${it.claimName}")
            }
            else -> throw Unauthorized("Unknown exception validating IdP Token: ${it.message}")
        }
    }

    private fun extractStringClaim(claims: Claims, claimName: String): String? {
        val value = resolveClaim(claims, claimName) ?: return null
        return value.toString()
    }

    private fun extractPrivileges(claims: Claims, claimName: String): List<String> {
        val value = resolveClaim(claims, claimName) ?: return emptyList()

        return when (value) {
            is String -> value.split(" ").filter { it.isNotBlank() }
            is Collection<*> -> value.mapNotNull { it?.toString() }
            else -> listOf(value.toString())
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun resolveClaim(claims: Claims, path: String): Any? {
        if ('.' !in path) {
            return claims[path]
        }

        val parts = path.split('.')
        var current: Any? = claims

        for (part in parts) {
            current = when (current) {
                is Map<*, *> -> current[part]
                else -> return null
            }
        }

        return current
    }
}
