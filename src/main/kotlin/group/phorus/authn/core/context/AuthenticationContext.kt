package group.phorus.authn.core.context

import group.phorus.authn.core.dtos.AuthenticationContextData

/**
 * Holds the authenticated user identity for the current request.
 * Access the current value via `AuthenticationContext.context.get()`.
 *
 * @see AuthenticationContextData
 */
object AuthenticationContext {
    val context: ThreadLocal<AuthenticationContextData> = ThreadLocal()
}
