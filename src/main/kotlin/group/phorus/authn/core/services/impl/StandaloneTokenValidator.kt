package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.AuthMode
import group.phorus.authn.core.config.AuthNConfig
import group.phorus.authn.core.config.TokenFormat
import group.phorus.authn.core.dtos.AuthData
import group.phorus.authn.core.dtos.TokenType
import group.phorus.authn.core.dtos.ExtraClaims
import group.phorus.authn.core.services.Authenticator
import group.phorus.authn.core.services.Validator
import group.phorus.exception.core.Unauthorized
import io.jsonwebtoken.*
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Multi-format [Authenticator] that validates tokens in any of the supported formats.
 *
 * Can be used directly
 * in any Kotlin/JVM application, or wrapped by a Spring bean in the starter.
 *
 * | Format | Detection | Validation |
 * |--------|-----------|------------|
 * | **JWS** | 3 Base64url segments | Signature verification using the configured signing public key. |
 * | **JWE** | 5 segments, no `cty: "JWT"` header | Decryption using the configured encryption private key. |
 * | **Nested JWE** | 5 segments, `cty: "JWT"` header | Decryption then inner JWS signature verification. |
 *
 * Token format is **auto-detected** at parse time (not tied to the creation-time config),
 * so a service can accept tokens from a previous deployment that used a different format.
 *
 * ### Validation flow
 * 1. Detect format by counting `.` separators.
 * 2. For JWE, peek at the unencrypted JOSE header to check for `cty: "JWT"`.
 * 3. Parse / decrypt / verify as appropriate.
 * 4. Extract standard claims (`sub`, `jti`, `scope`) and the custom `type` header.
 * 5. Run registered [Validator] instances (optional).
 * 6. Return [AuthData].
 *
 * @param config The authentication configuration containing JWT settings and key material.
 * @param validators List of [Validator] instances to run after claim extraction.
 * @see group.phorus.authn.core.services.Authenticator
 */
class StandaloneTokenValidator(
    private val config: AuthNConfig,
    private val validators: List<Validator>,
) : Authenticator {

    init {
        // Only validate keys when the service will actually validate own tokens
        if (config.mode != AuthMode.IDP_DELEGATED) {
            val format = config.jwt.tokenFormat

            // Validate decryption keys for formats that need them
            if (format == TokenFormat.JWE || format == TokenFormat.NESTED_JWE) {
                validateEncryptionConfig()
            }

            // Validate verification keys for formats that need them
            if (format == TokenFormat.JWS || format == TokenFormat.NESTED_JWE) {
                validateSigningConfig()
            }
        }
    }

    override fun authenticate(jwt: String, enableValidators: Boolean): AuthData {
        val enabledValidators = if (enableValidators) validators else emptyList()

        val (header, claims) = parseToken(jwt)

        val tokenType = header[ExtraClaims.TYPE]?.let { TokenType.valueOf(it.toString()) }
            ?: throw Unauthorized("Authentication failed, please log in again")

        val jti = claims.id
        val userId = claims.subject.let { UUID.fromString(it) }
        val privileges: List<String> = (claims["scope"] as? String)
            ?.split(" ") ?: emptyList()

        val properties = claims.map { (key, value) ->
            key to value.toString()
        }.toMap().also { props ->
            props.forEach { (key, value) ->
                enabledValidators.filter { it.accepts(key) }.forEach { validator ->
                    if (!validator.isValid(value, props))
                        throw Unauthorized("Authentication failed, please log in again")
                }
            }
        }

        return AuthData(
            userId = userId,
            tokenType = tokenType,
            jti = jti,
            privileges = privileges,
            properties = properties,
        )
    }

    override fun parseEncryptedClaims(jwt: String): Jwe<Claims> = decryptJweClaims(jwt)

    override fun parseSignedClaims(jwt: String): Jws<Claims> = verifyJws(jwt)

    /**
     * Auto-detects the token format and returns the merged header + claims.
     *
     * - 3 segments -> JWS
     * - 5 segments -> JWE, peeks at the unencrypted JOSE header for `cty: "JWT"` to detect nesting
     */
    private fun parseToken(jwt: String): Pair<Map<String, Any?>, Claims> {
        val segmentCount = jwt.count { it == '.' } + 1

        return when (segmentCount) {
            3 -> {
                val jws = verifyJws(jwt)
                Pair(jws.header.toMap(), jws.payload)
            }
            5 -> {
                // Peek at the unencrypted JOSE header to check for nested JWT
                val isNested = peekJweContentType(jwt).equals("JWT", ignoreCase = true)

                if (isNested) {
                    parseNestedJwe(jwt)
                } else {
                    val jwe = decryptJweClaims(jwt)
                    Pair(jwe.header.toMap(), jwe.payload)
                }
            }
            else -> throw Unauthorized("Invalid JWT Token")
        }
    }

    /**
     * Peeks at the first Base64url-encoded segment of a JWE to extract the `cty` (Content Type)
     * header parameter **without** performing decryption.
     *
     * The JOSE header of a JWE is not encrypted, it is only Base64url-encoded.
     * Per [RFC 7519 SS5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2),
     * a value of `"JWT"` indicates the payload is itself a JWT (nested JWT).
     *
     * @return The `cty` header value, or `null` if not present.
     */
    private fun peekJweContentType(jwt: String): String? {
        return runCatching {
            val headerSegment = jwt.substringBefore('.')
            val headerJson = Base64.getUrlDecoder().decode(headerSegment).toString(Charsets.UTF_8)

            // Simple extraction, avoids needing a JsonMapper for a single field
            val ctyRegex = """"cty"\s*:\s*"([^"]+)"""".toRegex()
            ctyRegex.find(headerJson)?.groupValues?.get(1)
        }.getOrNull()
    }

    /**
     * Parses a nested JWE: decrypts the outer JWE to obtain the inner JWS compact string,
     * then verifies the inner JWS signature and extracts claims.
     *
     * The outer JWE header's `type` claim (if present) takes precedence over the inner JWS header
     * so that the token type is always available regardless of format.
     */
    private fun parseNestedJwe(jwt: String): Pair<Map<String, Any?>, Claims> {
        // Decrypt the JWE, the payload is a JWS compact string, not JSON claims
        val (jweHeader, contentBytes) = decryptJweContent(jwt)

        // Verify the inner JWS
        val innerJwsString = contentBytes.toString(Charsets.UTF_8)
        val innerJws = verifyJws(innerJwsString)

        // Merge headers, outer JWE header wins for shared keys (e.g. `type`)
        val mergedHeader = buildMap {
            putAll(innerJws.header.toMap())
            putAll(jweHeader.toMap())
        }

        return Pair(mergedHeader, innerJws.payload)
    }

    private fun verifyJws(jwt: String): Jws<Claims> =
        runCatching {
            val publicKey = resolveSigningPublicKey()
            Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    /**
     * Decrypts a JWE whose payload is a JSON claims set (plain JWE mode).
     */
    private fun decryptJweClaims(jwt: String): Jwe<Claims> =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()
            Jwts.parser().decryptWith(privateKey).build().parseEncryptedClaims(jwt)
        }.getOrElse { handleParsingException(it) }

    /**
     * Decrypts a JWE and returns the raw decrypted bytes along with the JWE header.
     * Used for nested JWE where the payload is a JWS compact string, not a JSON claims set.
     */
    private fun decryptJweContent(jwt: String): Pair<JweHeader, ByteArray> =
        runCatching {
            val privateKey = resolveEncryptionPrivateKey()
            val jwe = Jwts.parser().decryptWith(privateKey).build().parseEncryptedContent(jwt)
            Pair(jwe.header, jwe.payload)
        }.getOrElse { handleParsingException(it) }

    private fun <T> handleParsingException(it: Throwable): T {
        when (it) {
            is SecurityException,
            is IllegalArgumentException,
            is MalformedJwtException,
            is UnsupportedJwtException -> throw Unauthorized("Invalid JWT Token")
            is ExpiredJwtException -> throw Unauthorized("JWT Token expired")
            else -> throw Unauthorized("Unknown exception related to the JWT Token: ${it.message}")
        }
    }

    private fun resolveSigningPublicKey(): PublicKey {
        val signing = config.jwt.signing
        val keyBytes = Base64.getDecoder().decode(signing.encodedPublicKey)
        val keyFactory = KeyFactory.getInstance(signing.algorithm)
        return keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    private fun resolveEncryptionPrivateKey(): java.security.PrivateKey {
        val enc = config.jwt.encryption
        val keyBytes = Base64.getDecoder().decode(enc.encodedPrivateKey)
        val keyFactory = KeyFactory.getInstance(enc.algorithm)
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    private fun validateEncryptionConfig() {
        val enc = config.jwt.encryption

        requireNotNull(enc.encodedPrivateKey) {
            "Encryption private key must be set for token format ${config.jwt.tokenFormat}"
        }

        require(Security.getAlgorithms("KeyFactory").any { it.equals(enc.algorithm, ignoreCase = true) }) {
            "Encryption algorithm '${enc.algorithm}' not found. Available: ${Security.getAlgorithms("KeyFactory")}"
        }

        require(Jwts.KEY.get().contains(enc.keyAlgorithm)) {
            "Encryption key algorithm '${enc.keyAlgorithm}' not found. Available: ${Jwts.KEY.get().keys}"
        }

        require(Jwts.ENC.get().contains(enc.aeadAlgorithm)) {
            "Encryption AEAD algorithm '${enc.aeadAlgorithm}' not found. Available: ${Jwts.ENC.get().keys}"
        }
    }

    private fun validateSigningConfig() {
        val signing = config.jwt.signing

        requireNotNull(signing.encodedPublicKey) {
            "Signing public key must be set for token format ${config.jwt.tokenFormat}"
        }

        require(Security.getAlgorithms("KeyFactory").any { it.equals(signing.algorithm, ignoreCase = true) }) {
            "Signing algorithm '${signing.algorithm}' not found. Available: ${Security.getAlgorithms("KeyFactory")}"
        }

        signing.signatureAlgorithm?.let { algId ->
            require(Jwts.SIG.get().contains(algId)) {
                "Signature algorithm '$algId' not found. Available: ${Jwts.SIG.get().keys}"
            }
        }
    }
}
