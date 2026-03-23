package group.phorus.authn.core.context

import group.phorus.authn.core.dtos.AuthContextData

/**
 * Holds the authenticated user identity for the current request.
 * Access the current value via `AuthContext.context.get()`.
 *
 * @see AuthContextData
 */
object AuthContext {
    val context: ThreadLocal<AuthContextData> = ThreadLocal()
}
