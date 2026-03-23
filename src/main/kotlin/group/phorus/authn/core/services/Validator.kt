package group.phorus.authn.core.services

/**
 * A pluggable claim validator that is invoked during token authentication.
 *
 * Implementations are auto-discovered as Spring beans. During [Authenticator.authenticate],
 * each registered [Validator] is given the opportunity to inspect specific token claims
 * and reject the token if validation fails.
 *
 * ### How it works
 * 1. After claims are extracted from the token, the authenticator iterates over all
 *    claim key-value pairs.
 * 2. For each pair, every registered [Validator] whose [accepts] method returns `true`
 *    for that claim key is invoked via [isValid].
 * 3. If **any** validator returns `false`, the token is rejected with a 401 Unauthorized.
 *
 * ### Example: device validator
 * ```kotlin
 * @Service
 * class DeviceValidator(
 *     private val deviceRepository: DeviceRepository,
 * ) : Validator {
 *     override fun accepts(property: String): Boolean = property == Claims.ID
 *
 *     override fun isValid(value: String, properties: Map<String, String>): Boolean =
 *         deviceRepository.findByJti(value)?.let { !it.disabled } ?: false
 * }
 * ```
 *
 * @see Authenticator
 */
interface Validator {
    /**
     * Returns `true` if this validator should be invoked for the given claim [property] key.
     *
     * @param property The claim key (e.g. `"jti"`, `"scope"`).
     */
    fun accepts(property: String): Boolean

    /**
     * Validates the claim [value] in the context of all extracted [properties].
     *
     * @param value The claim value to validate.
     * @param properties All extracted claim key-value pairs from the token (for cross-claim validation).
     * @return `true` if valid, `false` to reject the token.
     */
    fun isValid(value: String, properties: Map<String, String> = emptyMap()): Boolean
}
