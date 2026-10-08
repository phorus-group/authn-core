package group.phorus.authn.core.dtos

/**
 * An issued JWT access token together with the authority it carries.
 *
 * @property roles Subject entitlement, from the `roles` claim registered by
 *     [RFC 9068 SS7.2](https://datatracker.ietf.org/doc/html/rfc9068#section-7.2).
 * @property scope Delegated authority of the calling application, from the `scope` claim defined by
 *     [RFC 6749 SS3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
 */
data class AccessToken(
    val token: String,
    val roles: List<String> = emptyList(),
    val scope: List<String> = emptyList(),
)
