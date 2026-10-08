package group.phorus.authn.core.services

import group.phorus.authn.core.dtos.AccessToken
import java.util.*

/**
 * Creates access and refresh tokens in the configured
 * [token format][group.phorus.authn.core.config.TokenFormat].
 *
 * The concrete serialization (JWS, JWE, or nested JWE) is determined by the token format
 * configuration and is transparent to callers.
 *
 * The core implementation is
 * [TokenCreator][group.phorus.authn.core.services.impl.TokenCreator].
 */
interface TokenFactory {
    /**
     * Creates a short-lived access token for the given [userId].
     *
     * @param userId   Subject (`sub` claim): the authenticated user's identifier.
     * @param scope    Delegated authority of the calling application, written space-separated into the
     *     `scope` claim defined by
     *     [RFC 6749 SS3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
     * @param properties Additional custom claims to embed in the token payload.
     * @return An [AccessToken] containing the compact-serialized token string and the authority it carries.
     */
    suspend fun createAccessToken(userId: UUID, scope: List<String>, properties: Map<String, String> = emptyMap()): AccessToken

    /**
     * Creates a refresh token for the given [userId].
     *
     * Refresh tokens may be long-lived or non-expiring depending on [expires].
     *
     * @param userId   Subject (`sub` claim).
     * @param expires  When `true`, the token expires after the configured `refresh-token-minutes`,
     *                 when `false`, no `exp` claim is set.
     * @param properties Additional custom claims to embed in the token payload.
     * @return The compact-serialized refresh-token string.
     */
    suspend fun createRefreshToken(userId: UUID, expires: Boolean, properties: Map<String, String> = emptyMap()): String

    /**
     * Creates a short-lived access token carrying [claims] as the payload.
     *
     * A claim value keeps the type it is given, so a `List` is written as a JSON array and a `Map` as
     * a nested object. The registered names `jti`, `sub`, `iss`, `iat`, `exp`, `nbf` and `aud` belong
     * to the library and are rejected.
     *
     * An implementation of this interface must override this method.
     *
     * @param userId Subject (`sub` claim): the authenticated user's identifier.
     * @param claims Claims to write into the token payload.
     * @return An [AccessToken] containing the compact-serialized token string and the authority it carries.
     */
    suspend fun createAccessToken(userId: UUID, claims: Map<String, Any>): AccessToken =
        throw UnsupportedOperationException(
            "${this::class.simpleName} must override createAccessToken(userId, claims)"
        )

    /**
     * Creates a refresh token carrying [claims] as the payload, under the same rules as
     * [createAccessToken].
     *
     * An implementation of this interface must override this method.
     *
     * @param userId Subject (`sub` claim).
     * @param claims Claims to write into the token payload.
     * @param expires When `true`, the token expires after the configured `refresh-token-minutes`,
     *                when `false`, no `exp` claim is set.
     * @return The compact-serialized refresh-token string.
     */
    suspend fun createRefreshToken(userId: UUID, claims: Map<String, Any>, expires: Boolean): String =
        throw UnsupportedOperationException(
            "${this::class.simpleName} must override createRefreshToken(userId, claims, expires)"
        )
}
