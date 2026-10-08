package group.phorus.authn.core.dtos

import java.util.*

/**
 * Raw claims parsed from a validated JWT token, including its type and unique identifier.
 *
 * @property jti The unique token identifier (JWT ID claim).
 * @property roles Subject entitlement, from the `roles` claim registered by
 *     [RFC 9068 SS7.2](https://datatracker.ietf.org/doc/html/rfc9068#section-7.2).
 * @property scope Delegated authority of the calling application, from the `scope` claim defined by
 *     [RFC 6749 SS3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
 * @property properties Every claim in the token, with its value as the token carried it. A JSON array
 *     arrives as a `List`, a nested object as a `Map`, and a `NumericDate` claim such as `iat` or
 *     `exp` as a `Long` of seconds since the epoch per
 *     [RFC 7519 SS2](https://datatracker.ietf.org/doc/html/rfc7519#section-2).
 */
data class AuthData(
    var userId: UUID,
    var tokenType: TokenType,
    var jti: String,
    var roles: List<String> = emptyList(),
    var scope: List<String> = emptyList(),
    val properties: Map<String, Any?> = emptyMap(),
)
