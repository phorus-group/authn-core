package group.phorus.authn.core.services.impl

import io.jsonwebtoken.Claims

/**
 * Reads the claim at [path] as a list of strings, coping with every shape an issuer may use:
 * a space-delimited string per [RFC 6749 SS3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3),
 * a JSON array per [RFC 9068 SS2.2.3.1](https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1),
 * or a single scalar. Blank entries are dropped and a missing claim yields an empty list.
 *
 * [path] may use dot notation to read a nested claim, as Keycloak's `realm_access.roles` needs.
 */
internal fun extractClaimList(claims: Claims, path: String): List<String> {
    val value = resolveClaim(claims, path) ?: return emptyList()

    val raw = when (value) {
        is String -> value.split(" ")
        is Collection<*> -> value.mapNotNull { it?.toString() }
        else -> listOf(value.toString())
    }

    return raw.filter { it.isNotBlank() }
}

/**
 * Reads the claim at [path] as a single string, or `null` when it is absent.
 */
internal fun extractStringClaim(claims: Claims, path: String): String? =
    resolveClaim(claims, path)?.toString()

private fun resolveClaim(claims: Claims, path: String): Any? {
    if ('.' !in path) return claims[path]

    var current: Any? = claims
    for (part in path.split('.')) {
        current = when (current) {
            is Map<*, *> -> current[part]
            else -> return null
        }
    }

    return current
}
