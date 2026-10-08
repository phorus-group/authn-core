package group.phorus.authn.core.dtos

/**
 * Claim keys used in token headers.
 */
object ExtraClaims {
    /**
     * The `typ` JOSE header parameter, which holds the token's media type. Defined by
     * [RFC 7519 SS5.1](https://datatracker.ietf.org/doc/html/rfc7519#section-5.1) and valued per
     * [TokenType.mediaType].
     */
    const val TYPE = "typ"
}
