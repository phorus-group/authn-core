package group.phorus.authn.core.services

import group.phorus.authn.core.dtos.AuthData
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwe
import io.jsonwebtoken.Jws

/**
 * Validates a compact-serialized JWT and extracts authentication data.
 *
 * Two core implementations are provided:
 *
 * | Implementation | Key source |
 * |---------------|------------|
 * | [StandaloneTokenValidator][group.phorus.authn.core.services.impl.StandaloneTokenValidator] | Locally configured signing / encryption keys. |
 *
 * Both implementations auto-detect the token format (JWS / JWE / nested-JWE) at parse time
 * and run registered [Validator] instances after claim extraction.
 */
interface Authenticator {
    /**
     * Authenticates a compact-serialized JWT string and returns the extracted [AuthData].
     *
     * The token format (JWS / JWE / nested-JWE) is **auto-detected** based on the number of
     * Base64url segments (3 = JWS, 5 = JWE or nested-JWE).
     *
     * @param jwt              The compact-serialized token (without the `Bearer ` prefix).
     * @param enableValidators When `true` (default), registered [Validator] instances are invoked
     *                         after claim extraction. Set to `false` to skip custom validation.
     * @return Parsed [AuthData] containing user ID, token type, JTI, privileges, and custom properties.
     * @throws group.phorus.exception.core.Unauthorized on any validation failure.
     */
    fun authenticate(jwt: String, enableValidators: Boolean = true): AuthData

    /**
     * Low-level: parses a JWE token and returns the raw JJWT [Jwe] object.
     *
     * Only applicable when the token format includes encryption (JWE or nested-JWE).
     *
     * @param jwt The compact-serialized JWE token.
     * @return The decrypted [Jwe] containing [Claims].
     * @throws group.phorus.exception.core.Unauthorized on any parsing or decryption failure.
     */
    fun parseEncryptedClaims(jwt: String): Jwe<Claims>

    /**
     * Low-level: parses a JWS token and returns the raw JJWT [Jws] object.
     *
     * Only applicable when the token format is JWS.
     *
     * @param jwt The compact-serialized JWS token.
     * @return The verified [Jws] containing [Claims].
     * @throws group.phorus.exception.core.Unauthorized on any parsing or signature verification failure.
     */
    fun parseSignedClaims(jwt: String): Jws<Claims>
}
