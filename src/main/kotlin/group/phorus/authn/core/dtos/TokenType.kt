package group.phorus.authn.core.dtos

/**
 * Distinguishes between access tokens and refresh tokens.
 *
 * @property mediaType The value written into the `typ` JOSE header.
 */
enum class TokenType(val mediaType: String) {
    /** `at+jwt`, per [RFC 9068 SS2.2](https://datatracker.ietf.org/doc/html/rfc9068#section-2.2). */
    ACCESS_TOKEN("at+jwt"),

    /**
     * `rt+jwt`, a private media type belonging to this library. RFC 9068 covers access tokens, and
     * the value follows the `+jwt` structured suffix registered by
     * [RFC 6839 SS3.4](https://datatracker.ietf.org/doc/html/rfc6839#section-3.4).
     */
    REFRESH_TOKEN("rt+jwt");

    companion object {
        /**
         * Resolves a `typ` header value to the token type it names, or `null` for any other value.
         * Media type comparison is case-insensitive per
         * [RFC 9110 SS8.3.1](https://datatracker.ietf.org/doc/html/rfc9110#section-8.3.1).
         */
        fun fromMediaType(value: String): TokenType? =
            entries.firstOrNull { it.mediaType.equals(value, ignoreCase = true) }
    }
}
