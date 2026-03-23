package group.phorus.authn.core.dtos

/**
 * Represents an issued JWT access token along with the privileges it carries.
 */
data class AccessToken(
    val token: String,
    val privileges: List<String>,
)
