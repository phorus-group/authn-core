package group.phorus.authn.core.dtos

import java.time.Instant

/**
 * Captures HTTP request metadata for the current request. Accessible via
 * [group.phorus.authn.core.context.HTTPContext].
 */
data class HTTPContextData(
    val path: String,
    val method: String,
    val headers: Map<String, List<String>>,
    val queryParams: Map<String, List<String>>,
    val remoteAddress: String?,
    val timestamp: Instant = Instant.now(),
    val contentType: String? = null,
    val userAgent: String? = null,
    val origin: String? = null
)
