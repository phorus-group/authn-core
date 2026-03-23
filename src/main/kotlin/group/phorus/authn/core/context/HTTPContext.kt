package group.phorus.authn.core.context

import group.phorus.authn.core.dtos.HTTPContextData

/**
 * Holds HTTP request metadata for the current request.
 * Access the current value via `HTTPContext.context.get()`.
 *
 * @see HTTPContextData
 */
object HTTPContext {
    val context: ThreadLocal<HTTPContextData> = ThreadLocal()
}
