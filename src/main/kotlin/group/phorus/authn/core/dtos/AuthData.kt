package group.phorus.authn.core.dtos

import java.util.*

/**
 * Raw claims parsed from a validated JWT token, including its type and unique identifier.
 *
 * @property jti The unique token identifier (JWT ID claim).
 * @property properties Additional key-value claims extracted from the token.
 */
data class AuthData(
    var userId: UUID,
    var tokenType: TokenType,
    var jti: String,
    var privileges: List<String>,
    val properties: Map<String, String> = emptyMap(),
)
