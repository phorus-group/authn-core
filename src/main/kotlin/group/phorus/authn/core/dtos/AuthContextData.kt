package group.phorus.authn.core.dtos

import java.util.*

/**
 * Data available after successful token authentication. Accessible via
 * [group.phorus.authn.core.context.AuthContext].
 *
 * @property properties Additional key-value claims extracted from the token.
 */
data class AuthContextData(
    var userId: UUID,
    var privileges: List<String>,
    val properties: Map<String, String> = emptyMap(),
)
