package group.phorus.authn.core.context

import group.phorus.authn.core.dtos.ApiKeyContextData

/**
 * Holds the authenticated API key identity for the current request.
 * Access the current value via `ApiKeyContext.context.get()`.
 *
 * @see ApiKeyContextData
 */
object ApiKeyContext {
    val context: ThreadLocal<ApiKeyContextData> = ThreadLocal()
}
