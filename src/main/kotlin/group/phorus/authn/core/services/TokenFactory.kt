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
     * @param privileges Scopes / roles written into the `scope` claim, space-separated.
     * @param properties Additional custom claims to embed in the token payload.
     * @return An [AccessToken] containing the compact-serialized token string and the privilege list.
     */
    suspend fun createAccessToken(userId: UUID, privileges: List<String>, properties: Map<String, String> = emptyMap()): AccessToken

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
}
