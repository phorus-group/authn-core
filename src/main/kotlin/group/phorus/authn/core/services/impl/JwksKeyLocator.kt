package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.IdpConfig
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.LocatorAdapter
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.Key
import java.security.PublicKey
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * A JJWT [LocatorAdapter] that resolves JWS verification keys by fetching the
 * [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) from
 * an external Identity Provider's endpoint.
 *
 * Uses [java.net.http.HttpClient] for HTTP calls, so this class has no framework dependencies.
 *
 * ### Key resolution strategy
 * 1. Look up the `kid` (Key ID) from the JWS header in the local cache.
 * 2. If the key is **not** found and the cache has not been refreshed within the last
 *    cooldown period (30 seconds), fetch fresh keys from the JWKS endpoint.
 * 3. If the key is **still** not found after a refresh, throw an exception.
 *
 * ### Thread safety
 * All cache operations are protected by a [ReentrantReadWriteLock].
 *
 * **Note:** The [locate] and [forceRefresh] methods perform blocking HTTP calls.
 * When calling from a coroutine context, wrap in `withContext(Dispatchers.IO)`.
 *
 * @param config The IdP configuration containing the JWKS endpoint URI and cache TTL.
 * @param httpClient The HTTP client used to fetch JWKS. Defaults to a new instance.
 */
class JwksKeyLocator(
    private val config: IdpConfig,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
) : LocatorAdapter<Key>() {

    private val log = LoggerFactory.getLogger(JwksKeyLocator::class.java)

    private val keyCache = ConcurrentHashMap<String, PublicKey>()

    @Volatile
    private var lastFetchTime: Instant = Instant.EPOCH

    private val lock = ReentrantReadWriteLock()

    private val cacheTtl = Duration.ofMinutes(config.jwksCacheTtlMinutes)

    private val refreshCooldown = Duration.ofSeconds(30)

    override fun locate(header: JwsHeader): Key {
        val kid = header.keyId
            ?: throw SecurityException("JWS token is missing the 'kid' (Key ID) header parameter")

        lock.read {
            keyCache[kid]?.let { return it }
        }

        refreshKeysIfNeeded()

        return lock.read {
            keyCache[kid]
                ?: throw SecurityException(
                    "No key found for kid '$kid' in JWKS from ${config.jwkSetUri}. " +
                    "Available kids: ${keyCache.keys}"
                )
        }
    }

    fun forceRefresh() {
        lock.write {
            fetchAndCacheKeys()
        }
    }

    private fun refreshKeysIfNeeded() {
        val now = Instant.now()
        val minRefreshInterval = maxOf(cacheTtl, refreshCooldown)

        if (Duration.between(lastFetchTime, now) < minRefreshInterval) {
            return
        }

        lock.write {
            val timeSinceLastFetch = Duration.between(lastFetchTime, now)
            if (timeSinceLastFetch < minRefreshInterval) {
                return
            }

            fetchAndCacheKeys()
        }
    }

    private fun fetchAndCacheKeys() {
        val jwkSetUri = config.jwkSetUri
            ?: throw IllegalStateException(
                "group.phorus.security.idp.jwk-set-uri must be configured for IdP modes"
            )

        log.debug("Fetching JWKS from {}", jwkSetUri)

        val jwksJson = runCatching {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(jwkSetUri))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build()
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            val body = response.body()
            if (response.statusCode() != 200 || body.isNullOrEmpty()) {
                throw IllegalStateException(
                    "JWKS endpoint returned HTTP ${response.statusCode()}: $jwkSetUri"
                )
            }
            body
        }.getOrElse { ex ->
            if (ex is SecurityException) throw ex
            log.error("Failed to fetch JWKS from {}: {}", jwkSetUri, ex.message)
            throw SecurityException("Failed to fetch JWKS from $jwkSetUri: ${ex.message}", ex)
        }

        val jwkSet = runCatching {
            Jwks.setParser().build().parse(jwksJson)
        }.getOrElse { ex ->
            log.error("Failed to parse JWKS from {}: {}", jwkSetUri, ex.message)
            throw SecurityException("Failed to parse JWKS from $jwkSetUri: ${ex.message}", ex)
        }

        val newKeys = ConcurrentHashMap<String, PublicKey>()
        for (jwk in (jwkSet as Iterable<Jwk<*>>)) {
            val kid = jwk.id ?: continue
            val key = jwk.toKey()
            if (key is PublicKey) {
                newKeys[kid] = key
            }
        }

        log.debug("Fetched {} public keys from JWKS: kids={}", newKeys.size, newKeys.keys)

        keyCache.clear()
        keyCache.putAll(newKeys)
        lastFetchTime = Instant.now()
    }
}
