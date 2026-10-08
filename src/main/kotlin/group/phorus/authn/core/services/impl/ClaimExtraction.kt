package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.ClaimsMapping
import io.jsonwebtoken.Claims

/**
 * Reads the claim at [path] as a list of strings, coping with every shape an issuer may use:
 * a space-delimited string per [RFC 6749 SS3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3),
 * a JSON array per [RFC 9068 SS2.2.3.1](https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1),
 * or a single scalar. Blank entries are dropped and a missing claim yields an empty list.
 *
 * [path] may use dot notation to read a nested claim, as Keycloak's `realm_access.roles` needs.
 */
internal fun extractClaimList(claims: Claims, path: String): List<String> =
    toClaimList(resolveClaim(claims, path))

/**
 * Reads one claim value as a list of strings, under the same rules as [extractClaimList].
 */
internal fun toClaimList(value: Any?): List<String> {
    if (value == null) return emptyList()

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

/**
 * Requires the claim names this library writes to be flat.
 *
 * A dot means different things on each side. Writing puts the name at the top level of the payload,
 * so `realm_access.roles` becomes one key containing a dot:
 *
 * ```json
 * { "realm_access.roles": ["ADMIN"] }
 * ```
 *
 * Reading treats the dot as a path and looks for `roles` inside an object called `realm_access`:
 *
 * ```json
 * { "realm_access": { "roles": ["ADMIN"] } }
 * ```
 *
 * The reader would find nothing and return an empty list, so a dotted name is refused here. A name
 * used only for reading may be dotted, since there the nesting comes from whoever issued the token.
 */
internal fun requireFlatClaimNames(claims: ClaimsMapping) {
    val nested = listOf("subject" to claims.subject, "scope" to claims.scope, "roles" to claims.roles)
        .filter { '.' in it.second }

    require(nested.isEmpty()) {
        val names = nested.joinToString(", ") { "${it.first}=${it.second}" }
        "Dot notation is only available for an IdP's claim names, so jwt.claims needs flat names: $names"
    }
}

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
