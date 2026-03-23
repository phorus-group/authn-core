package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.AuthMode
import group.phorus.authn.core.config.AuthNConfig
import group.phorus.authn.core.config.TokenFormat
import group.phorus.authn.core.dtos.AccessToken
import group.phorus.authn.core.dtos.TokenType
import group.phorus.authn.core.dtos.ExtraClaims
import group.phorus.authn.core.services.TokenFactory
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.KeyAlgorithm
import io.jsonwebtoken.security.SecureDigestAlgorithm
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*

/**
 * Creates access and refresh tokens in the format determined by
 * [AuthNConfig.jwt.tokenFormat][group.phorus.authn.core.config.JwtConfig.tokenFormat].
 *
 * Can be used directly
 * in any Kotlin/JVM application, or wrapped by a Spring bean in the starter.
 *
 * ### Supported formats
 *
 * | Format | What is produced |
 * |--------|-----------------|
 * | [TokenFormat.JWS] | A signed JWT (3 Base64url segments). Claims are **visible** but tamper-proof. |
 * | [TokenFormat.JWE] | An encrypted JWT (5 Base64url segments). Claims are **confidential** but not independently signed. |
 * | [TokenFormat.NESTED_JWE] | A JWS wrapped inside a JWE (sign-then-encrypt). Provides **both** integrity and confidentiality. The outer JWE header contains `cty: "JWT"` per [RFC 7519 SS5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2). |
 *
 * @param config The authentication configuration containing JWT settings, key material, and expiration.
 * @see group.phorus.authn.core.services.TokenFactory
 */
class TokenCreator(
    private val config: AuthNConfig,
) : TokenFactory {

    private val tokenFormat: TokenFormat get() = config.jwt.tokenFormat

    init {
        // Only validate keys when the service will actually create tokens
        if (config.mode != AuthMode.IDP_DELEGATED) {
            val format = config.jwt.tokenFormat

            if (format == TokenFormat.JWE || format == TokenFormat.NESTED_JWE) {
                validateEncryptionConfig()
            }

            if (format == TokenFormat.JWS || format == TokenFormat.NESTED_JWE) {
                validateSigningConfig()
            }
        }
    }

    override suspend fun createAccessToken(
        userId: UUID,
        privileges: List<String>,
        properties: Map<String, String>,
    ): AccessToken {
        val currentTime = Instant.now()
        val expiration = currentTime.plusSeconds(config.jwt.expiration.tokenMinutes * 60)

        val claimsMap = buildClaimsMap(
            tokenType = TokenType.ACCESS_TOKEN,
            userId = userId,
            currentTime = currentTime,
            expiration = expiration,
            privileges = privileges,
            properties = properties,
        )

        val token = buildToken(claimsMap, TokenType.ACCESS_TOKEN)

        return AccessToken(
            token = token,
            privileges = privileges,
        )
    }

    override suspend fun createRefreshToken(
        userId: UUID,
        expires: Boolean,
        properties: Map<String, String>,
    ): String {
        val currentTime = Instant.now()
        val expiration = if (expires) {
            currentTime.plusSeconds(config.jwt.expiration.refreshTokenMinutes * 60)
        } else null

        val claimsMap = buildClaimsMap(
            tokenType = TokenType.REFRESH_TOKEN,
            userId = userId,
            currentTime = currentTime,
            expiration = expiration,
            privileges = null,
            properties = properties,
        )

        return buildToken(claimsMap, TokenType.REFRESH_TOKEN)
    }

    private fun buildToken(claimsMap: Map<String, Any>, tokenType: TokenType): String =
        when (tokenFormat) {
            TokenFormat.JWS -> buildJws(claimsMap, tokenType)
            TokenFormat.JWE -> buildJwe(claimsMap, tokenType)
            TokenFormat.NESTED_JWE -> buildNestedJwe(claimsMap, tokenType)
        }

    /**
     * Builds a signed-only JWT (JWS).
     */
    private fun buildJws(claimsMap: Map<String, Any>, tokenType: TokenType): String {
        val signingKey = resolveSigningPrivateKey()
        val sigAlg = resolveSignatureAlgorithm()

        val builder = Jwts.builder()
            .header()
                .add(ExtraClaims.TYPE, tokenType.name)
            .and()
            .claims()
                .add(claimsMap)
            .and()

        @Suppress("UNCHECKED_CAST")
        return if (sigAlg != null) {
            builder.signWith(signingKey, sigAlg as SecureDigestAlgorithm<in PrivateKey, *>).compact()
        } else {
            builder.signWith(signingKey).compact()
        }
    }

    /**
     * Builds an encrypted-only JWT (JWE).
     */
    @Suppress("UNCHECKED_CAST")
    private fun buildJwe(claimsMap: Map<String, Any>, tokenType: TokenType): String {
        val publicKey = resolveEncryptionPublicKey()
        val enc = config.jwt.encryption

        return Jwts.builder()
            .header()
                .add(ExtraClaims.TYPE, tokenType.name)
            .and()
            .claims()
                .add(claimsMap)
            .and()
            .encryptWith(
                publicKey,
                Jwts.KEY.get().forKey(enc.keyAlgorithm) as KeyAlgorithm<PublicKey, PrivateKey>,
                Jwts.ENC.get().forKey(enc.aeadAlgorithm),
            )
            .compact()
    }

    /**
     * Builds a nested JWE: signs claims as JWS first, then encrypts the JWS as JWE payload.
     *
     * The outer JWE header includes `cty: "JWT"` per RFC 7519 SS5.2 to indicate that the
     * encrypted content is itself a JWT.
     */
    @Suppress("UNCHECKED_CAST")
    private fun buildNestedJwe(claimsMap: Map<String, Any>, tokenType: TokenType): String {
        // Build the inner JWS
        val innerJws = buildJws(claimsMap, tokenType)

        // Wrap the JWS inside a JWE with cty: "JWT"
        val publicKey = resolveEncryptionPublicKey()
        val enc = config.jwt.encryption

        return Jwts.builder()
            .header()
                .contentType("JWT")
                .add(ExtraClaims.TYPE, tokenType.name)
            .and()
            .content(innerJws.toByteArray())
            .encryptWith(
                publicKey,
                Jwts.KEY.get().forKey(enc.keyAlgorithm) as KeyAlgorithm<PublicKey, PrivateKey>,
                Jwts.ENC.get().forKey(enc.aeadAlgorithm),
            )
            .compact()
    }

    private fun buildClaimsMap(
        tokenType: TokenType,
        userId: UUID,
        currentTime: Instant,
        expiration: Instant?,
        privileges: List<String>?,
        properties: Map<String, String>,
    ): Map<String, Any> = buildMap {
        val jti = UUID.randomUUID().toString()

        put("jti", jti)
        put("sub", userId.toString())
        config.jwt.issuer?.let { put("iss", it) }
        put("iat", Date.from(currentTime))
        expiration?.let { put("exp", Date.from(it)) }
        privileges?.let { put("scope", it.joinToString(" ")) }
        properties.forEach { (key, value) -> put(key, value) }
    }

    private fun resolveSigningPrivateKey(): PrivateKey {
        val signing = config.jwt.signing
        val keyBytes = Base64.getDecoder().decode(signing.encodedPrivateKey)
        val keyFactory = KeyFactory.getInstance(signing.algorithm)
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    private fun resolveEncryptionPublicKey(): PublicKey {
        val enc = config.jwt.encryption
        val keyBytes = Base64.getDecoder().decode(enc.encodedPublicKey)
        val keyFactory = KeyFactory.getInstance(enc.algorithm)
        return keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    private fun resolveSignatureAlgorithm() =
        config.jwt.signing.signatureAlgorithm?.let { algId ->
            Jwts.SIG.get().forKey(algId)
        }

    private fun validateEncryptionConfig() {
        val enc = config.jwt.encryption

        requireNotNull(enc.encodedPublicKey) {
            "Encryption public key must be set for token format $tokenFormat"
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

        requireNotNull(signing.encodedPrivateKey) {
            "Signing private key must be set for token format $tokenFormat"
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
