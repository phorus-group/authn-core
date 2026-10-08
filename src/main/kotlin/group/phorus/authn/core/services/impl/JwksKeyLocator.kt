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
import java.time.Clock
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
 * 1. A cached key younger than [IdpConfig.jwksCacheTtlMinutes] is returned straight away.
 * 2. Anything else, an unknown `kid` or a cache past its TTL, fetches fresh keys, as long as the last
 *    attempt was more than the 30-second cooldown ago. The cooldown bounds how often a lookup reaches
 *    the endpoint, and the TTL bounds how stale a key can be before a refresh is attempted.
 * 3. A failed fetch still serves the cached key for a `kid` the cache holds, so an outage at the
 *    issuer costs freshness instead of every authenticated request. A `kid` the cache does not hold
 *    throws, since there is nothing to serve and the fetch failure is the useful diagnostic.
 *
 * A key rotation at the issuer therefore takes effect within the cooldown, which is what a token
 * signed by a brand-new `kid` needs.
 *
 * ### Thread safety
 * All cache operations are protected by a [ReentrantReadWriteLock].
 *
 * **Note:** The [locate] and [forceRefresh] methods perform blocking HTTP calls.
 * When calling from a coroutine context, wrap in `withContext(Dispatchers.IO)`.
 *
 * @param config The IdP configuration containing the JWKS endpoint URI and cache TTL.
 * @param httpClient The HTTP client used to fetch JWKS. Defaults to a new instance.
 * @param clock The source of time for the cache TTL and the refresh cooldown.
 */
class JwksKeyLocator(
    private val config: IdpConfig,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val clock: Clock = Clock.systemUTC(),
) : LocatorAdapter<Key>() {

    private val log = LoggerFactory.getLogger(JwksKeyLocator::class.java)

    private val keyCache = ConcurrentHashMap<String, PublicKey>()

    @Volatile
    private var lastFetchTime: Instant = Instant.EPOCH

    @Volatile
    private var lastAttemptTime: Instant = Instant.EPOCH

    private val lock = ReentrantReadWriteLock()

    private val cacheTtl = Duration.ofMinutes(config.jwksCacheTtlMinutes)

    private val refreshCooldown = Duration.ofSeconds(30)

    override fun locate(header: JwsHeader): Key {
        val kid = header.keyId
            ?: throw SecurityException("JWS token is missing the 'kid' (Key ID) header parameter")

        if (!isCacheExpired()) {
            lock.read {
                keyCache[kid]?.let { return it }
            }
        }

        val cached = lock.read { keyCache[kid] }

        runCatching { refreshKeysIfNeeded() }.onFailure {
            if (cached == null) throw it
            log.warn("Serving a stale key for kid '{}', JWKS refresh failed: {}", kid, it.message)
        }

        return lock.read { keyCache[kid] }
            ?: cached
            ?: throw SecurityException(
                "No key found for kid '$kid' in JWKS from ${config.jwkSetUri}. " +
                "Available kids: ${keyCache.keys}"
            )
    }

    fun forceRefresh() {
        lock.write {
            fetchAndCacheKeys()
        }
    }

    private fun isCacheExpired(): Boolean =
        Duration.between(lastFetchTime, clock.instant()) >= cacheTtl

    private fun refreshKeysIfNeeded() {
        if (Duration.between(lastAttemptTime, clock.instant()) < refreshCooldown) {
            return
        }

        lock.write {
            if (Duration.between(lastAttemptTime, clock.instant()) < refreshCooldown) {
                return
            }

            lastAttemptTime = clock.instant()
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
        lastFetchTime = clock.instant()
    }
}
