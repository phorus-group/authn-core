package group.phorus.authn.core.config

/**
 * Authentication mode that determines how tokens are created and validated.
 *
 * @see AuthNConfig.mode
 */
enum class AuthMode {
    /**
     * The service manages its own tokens end-to-end.
     * Requires [SigningConfig] and/or [EncryptionConfig] depending on the chosen [TokenFormat].
     */
    STANDALONE,

    /**
     * An external IdP issues the initial token. After validation, the service creates its own
     * tokens for internal use. Requires both [IdpConfig] **and** signing/encryption keys.
     */
    IDP_BRIDGE,

    /**
     * The service only validates IdP-issued tokens, it never mints its own.
     * Requires [IdpConfig]. Token refresh is the IdP's responsibility.
     */
    IDP_DELEGATED,
}

/**
 * Token serialization format used when creating tokens.
 *
 * @see JwtConfig.tokenFormat
 */
enum class TokenFormat {
    /** Signed-only JWT (JWS). Three Base64url segments. */
    JWS,

    /** Encrypted-only JWT (JWE). Five Base64url segments. No inner signature. */
    JWE,

    /**
     * A JWS wrapped inside a JWE (sign-then-encrypt).
     * The outer JWE header contains `cty: "JWT"` per [RFC 7519 SS5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2).
     */
    NESTED_JWE,
}

/**
 * Configuration data classes for authentication, used by
 * [TokenCreator][group.phorus.authn.core.services.impl.TokenCreator] and
 * [StandaloneTokenValidator][group.phorus.authn.core.services.impl.StandaloneTokenValidator].
 *
 * Can be constructed directly or populated from configuration.
 *
 * @property mode Authentication mode. Defaults to [AuthMode.STANDALONE].
 * @property jwt JWT creation, parsing, signing, and encryption settings.
 * @property idp External Identity Provider settings. Required when [mode] is [AuthMode.IDP_BRIDGE] or [AuthMode.IDP_DELEGATED].
 */
data class AuthNConfig(
    val mode: AuthMode = AuthMode.STANDALONE,
    val jwt: JwtConfig = JwtConfig(),
    val idp: IdpConfig = IdpConfig(),
)

/**
 * JWT-level configuration: issuer, token format, signing keys, encryption keys, and expiration.
 *
 * @property issuer The `iss` (issuer) claim written into every token created by this library.
 *     Also used to validate incoming tokens in [AuthMode.STANDALONE] and [AuthMode.IDP_BRIDGE] modes.
 * @property tokenFormat Token serialization format. Defaults to [TokenFormat.JWS].
 * @property signing Signing key material. Required when [tokenFormat] is [TokenFormat.JWS] or [TokenFormat.NESTED_JWE].
 * @property encryption Encryption key material. Required when [tokenFormat] is [TokenFormat.JWE] or [TokenFormat.NESTED_JWE].
 * @property expiration Access-token and refresh-token lifetimes.
 */
data class JwtConfig(
    val issuer: String? = null,
    val tokenFormat: TokenFormat = TokenFormat.JWS,
    val signing: SigningConfig = SigningConfig(),
    val encryption: EncryptionConfig = EncryptionConfig(),
    val expiration: ExpirationConfig = ExpirationConfig(),
)

/**
 * Signing key configuration for JWS and nested-JWE token formats.
 *
 * Uses asymmetric key pairs: the private key signs tokens, the public key verifies them.
 *
 * @property algorithm JCA key-factory algorithm name (e.g. `"EC"`, `"RSA"`).
 * @property signatureAlgorithm JJWT signature algorithm identifier (e.g. `"ES384"`, `"RS256"`).
 *     When `null`, JJWT selects the strongest algorithm supported by the key.
 * @property encodedPrivateKey Base64-encoded PKCS#8 private key used for **signing**.
 * @property encodedPublicKey Base64-encoded X.509 public key used for **verification**.
 */
data class SigningConfig(
    val algorithm: String = "EC",
    val signatureAlgorithm: String? = null,
    val encodedPrivateKey: String? = null,
    val encodedPublicKey: String? = null,
)

/**
 * Encryption key configuration for JWE and nested-JWE token formats.
 *
 * Uses asymmetric key pairs: the public key encrypts tokens, the private key decrypts them.
 *
 * @property algorithm JCA key-factory algorithm name (e.g. `"EC"`, `"RSA"`).
 * @property keyAlgorithm JJWT key-management algorithm identifier (e.g. `"ECDH-ES+A256KW"`, `"RSA-OAEP-256"`).
 * @property aeadAlgorithm JJWT content-encryption (AEAD) algorithm identifier (e.g. `"A256CBC-HS512"`, `"A192CBC-HS384"`).
 * @property encodedPublicKey Base64-encoded X.509 public key used for **encryption**.
 * @property encodedPrivateKey Base64-encoded PKCS#8 private key used for **decryption**.
 */
data class EncryptionConfig(
    val algorithm: String = "EC",
    val keyAlgorithm: String = "ECDH-ES+A256KW",
    val aeadAlgorithm: String = "A192CBC-HS384",
    val encodedPublicKey: String? = null,
    val encodedPrivateKey: String? = null,
)

/**
 * Token lifetime configuration.
 *
 * @property tokenMinutes Access-token lifetime in minutes. Defaults to `10`.
 * @property refreshTokenMinutes Refresh-token lifetime in minutes. Defaults to `1440` (24 h).
 */
data class ExpirationConfig(
    val tokenMinutes: Long = 10,
    val refreshTokenMinutes: Long = 1440,
)

/**
 * External Identity Provider (IdP) configuration.
 *
 * Required when [AuthNConfig.mode] is [AuthMode.IDP_BRIDGE] or [AuthMode.IDP_DELEGATED].
 *
 * @property issuerUri The IdP's issuer identifier (e.g. `https://idp.example.com`).
 *     Used to validate the `iss` claim of incoming IdP tokens.
 * @property jwkSetUri URL of the IdP's JWKS endpoint.
 * @property jwksCacheTtlMinutes How long fetched JWKS keys are cached before a refresh. Defaults to `60`.
 * @property claims Mapping from IdP claim names to the internal representation.
 */
data class IdpConfig(
    val issuerUri: String? = null,
    val jwkSetUri: String? = null,
    val jwksCacheTtlMinutes: Long = 60,
    val claims: ClaimsMapping = ClaimsMapping(),
)

/**
 * Maps IdP token claim names to the internal claim names expected by auth-commons.
 *
 * Different IdPs use different claim names (e.g. Keycloak uses `realm_access.roles`,
 * Auth0 uses `permissions`, Azure AD uses `roles`). This mapping normalizes them.
 *
 * @property subject The claim that contains the user identifier. Defaults to `"sub"`.
 * @property privileges The claim that contains scopes / roles / permissions. Defaults to `"scope"`.
 */
data class ClaimsMapping(
    val subject: String = "sub",
    val privileges: String = "scope",
)
