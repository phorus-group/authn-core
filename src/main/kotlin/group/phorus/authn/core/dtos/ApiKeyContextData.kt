package group.phorus.authn.core.dtos

/**
 * Data available after successful API key authentication. Accessible via
 * [group.phorus.authn.core.context.ApiKeyContext].
 *
 * @property keyId The resolved identifier of the API key.
 * @property metadata Additional key-value metadata. Empty when using static keys.
 */
data class ApiKeyContextData(
    val keyId: String?,
    val metadata: Map<String, String> = emptyMap(),
)
