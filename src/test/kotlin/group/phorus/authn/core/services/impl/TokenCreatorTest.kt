package group.phorus.authn.core.services.impl

import group.phorus.authn.core.config.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.*

/**
 * Validates that all documented algorithm combinations produce working tokens.
 *
 * Each test generates a fresh key pair using the JCA (same PKCS#8 / X.509 format
 * that OpenSSL produces), creates a token with [TokenCreator], and parses it
 * back with [StandaloneTokenValidator]. This proves the algorithm + key-format combination
 * is correct end-to-end.
 */
class TokenCreatorTest {

    companion object {
        private const val ISSUER = "algorithm-test"
        private val TEST_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000099")

        private fun ecKeyPair(curve: String): Pair<String, String> {
            val kp = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec(curve))
            }.generateKeyPair()
            return Pair(
                Base64.getEncoder().encodeToString(kp.private.encoded),
                Base64.getEncoder().encodeToString(kp.public.encoded),
            )
        }

        private fun rsaKeyPair(bits: Int): Pair<String, String> {
            val kp = KeyPairGenerator.getInstance("RSA").apply {
                initialize(bits)
            }.generateKeyPair()
            return Pair(
                Base64.getEncoder().encodeToString(kp.private.encoded),
                Base64.getEncoder().encodeToString(kp.public.encoded),
            )
        }

        private fun eddsaKeyPair(curve: String): Pair<String, String> {
            val kp = KeyPairGenerator.getInstance(curve).generateKeyPair()
            return Pair(
                Base64.getEncoder().encodeToString(kp.private.encoded),
                Base64.getEncoder().encodeToString(kp.public.encoded),
            )
        }

        private fun roundTrip(config: AuthNConfig) = runBlocking {
            val factory = TokenCreator(config)
            val authenticator = StandaloneTokenValidator(config, emptyList())

            val accessToken = factory.createAccessToken(TEST_USER_ID, listOf("read", "write"))
            val claims = authenticator.authenticate(accessToken.token)

            assertEquals(TEST_USER_ID, claims.userId)
        }
    }

    @Nested
    @DisplayName("Signing: EC P-256 / ES256")
    inner class EcP256Signing {
        @Test
        fun `JWS round-trip with EC P-256`() {
            val (priv, pub) = ecKeyPair("secp256r1")
            roundTrip(config(TokenFormat.JWS, sigAlg = "EC", sigSigAlg = "ES256", sigPriv = priv, sigPub = pub))
        }
    }

    @Nested
    @DisplayName("Signing: EC P-384 / ES384 (default)")
    inner class EcP384Signing {
        @Test
        fun `JWS round-trip with EC P-384 explicit ES384`() {
            val (priv, pub) = ecKeyPair("secp384r1")
            roundTrip(config(TokenFormat.JWS, sigAlg = "EC", sigSigAlg = "ES384", sigPriv = priv, sigPub = pub))
        }

        @Test
        fun `JWS round-trip with EC P-384 auto-detected algorithm`() {
            val (priv, pub) = ecKeyPair("secp384r1")
            roundTrip(config(TokenFormat.JWS, sigAlg = "EC", sigSigAlg = null, sigPriv = priv, sigPub = pub))
        }
    }

    @Nested
    @DisplayName("Signing: EC P-521 / ES512")
    inner class EcP521Signing {
        @Test
        fun `JWS round-trip with EC P-521`() {
            val (priv, pub) = ecKeyPair("secp521r1")
            roundTrip(config(TokenFormat.JWS, sigAlg = "EC", sigSigAlg = "ES512", sigPriv = priv, sigPub = pub))
        }
    }

    @Nested
    @DisplayName("Signing: RSA 2048")
    inner class Rsa2048Signing {
        private val keys = rsaKeyPair(2048)

        @Test
        fun `JWS round-trip with RS256`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "RS256", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with RS384`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "RS384", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with RS512`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "RS512", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with PS256`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "PS256", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with PS384`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "PS384", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with PS512`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = "PS512", sigPriv = keys.first, sigPub = keys.second))
        }

        @Test
        fun `JWS round-trip with RSA auto-detected algorithm`() {
            roundTrip(config(TokenFormat.JWS, sigAlg = "RSA", sigSigAlg = null, sigPriv = keys.first, sigPub = keys.second))
        }
    }

    @Nested
    @DisplayName("Signing: EdDSA (Ed25519)")
    inner class Ed25519Signing {
        @Test
        fun `JWS round-trip with Ed25519`() {
            val (priv, pub) = eddsaKeyPair("Ed25519")
            roundTrip(config(TokenFormat.JWS, sigAlg = "Ed25519", sigSigAlg = "EdDSA", sigPriv = priv, sigPub = pub))
        }

        @Test
        fun `JWS round-trip with Ed25519 auto-detected`() {
            val (priv, pub) = eddsaKeyPair("Ed25519")
            roundTrip(config(TokenFormat.JWS, sigAlg = "Ed25519", sigSigAlg = null, sigPriv = priv, sigPub = pub))
        }
    }

    @Nested
    @DisplayName("Signing: EdDSA (Ed448)")
    inner class Ed448Signing {
        @Test
        fun `JWS round-trip with Ed448`() {
            val (priv, pub) = eddsaKeyPair("Ed448")
            roundTrip(config(TokenFormat.JWS, sigAlg = "Ed448", sigSigAlg = "EdDSA", sigPriv = priv, sigPub = pub))
        }
    }

    @Nested
    @DisplayName("Encryption: EC ECDH-ES variants")
    inner class EcEncryption {
        @Test
        fun `JWE with ECDH-ES+A256KW and A192CBC-HS384 (default)`() {
            val (priv, pub) = ecKeyPair("secp384r1")
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "EC", encKeyAlg = "ECDH-ES+A256KW", encAeadAlg = "A192CBC-HS384",
                encPriv = priv, encPub = pub,
            ))
        }

        @Test
        fun `JWE with ECDH-ES+A128KW and A128CBC-HS256`() {
            val (priv, pub) = ecKeyPair("secp256r1")
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "EC", encKeyAlg = "ECDH-ES+A128KW", encAeadAlg = "A128CBC-HS256",
                encPriv = priv, encPub = pub,
            ))
        }

        @Test
        fun `JWE with ECDH-ES+A192KW and A256GCM`() {
            val (priv, pub) = ecKeyPair("secp384r1")
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "EC", encKeyAlg = "ECDH-ES+A192KW", encAeadAlg = "A256GCM",
                encPriv = priv, encPub = pub,
            ))
        }

        @Test
        fun `JWE with ECDH-ES (direct) and A256GCM`() {
            val (priv, pub) = ecKeyPair("secp384r1")
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "EC", encKeyAlg = "ECDH-ES", encAeadAlg = "A256GCM",
                encPriv = priv, encPub = pub,
            ))
        }
    }

    @Nested
    @DisplayName("Encryption: RSA variants")
    inner class RsaEncryption {
        private val rsaKeys = rsaKeyPair(2048)

        @Test
        fun `JWE with RSA-OAEP-256 and A256GCM`() {
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "RSA", encKeyAlg = "RSA-OAEP-256", encAeadAlg = "A256GCM",
                encPriv = rsaKeys.first, encPub = rsaKeys.second,
            ))
        }

        @Test
        fun `JWE with RSA-OAEP and A256CBC-HS512`() {
            roundTrip(config(
                TokenFormat.JWE,
                encAlg = "RSA", encKeyAlg = "RSA-OAEP", encAeadAlg = "A256CBC-HS512",
                encPriv = rsaKeys.first, encPub = rsaKeys.second,
            ))
        }
    }

    @Nested
    @DisplayName("Nested JWE: EC signing + EC encryption")
    inner class NestedJweEcEc {
        @Test
        fun `nested JWE with EC P-384 signing and EC P-384 encryption`() {
            val (sigPriv, sigPub) = ecKeyPair("secp384r1")
            val (encPriv, encPub) = ecKeyPair("secp384r1")
            roundTrip(config(
                TokenFormat.NESTED_JWE,
                sigAlg = "EC", sigSigAlg = "ES384", sigPriv = sigPriv, sigPub = sigPub,
                encAlg = "EC", encKeyAlg = "ECDH-ES+A256KW", encAeadAlg = "A192CBC-HS384",
                encPriv = encPriv, encPub = encPub,
            ))
        }
    }

    @Nested
    @DisplayName("Nested JWE: RSA signing + RSA encryption")
    inner class NestedJweRsaRsa {
        @Test
        fun `nested JWE with RSA signing and RSA encryption`() {
            val (sigPriv, sigPub) = rsaKeyPair(2048)
            val (encPriv, encPub) = rsaKeyPair(2048)
            roundTrip(config(
                TokenFormat.NESTED_JWE,
                sigAlg = "RSA", sigSigAlg = "PS256", sigPriv = sigPriv, sigPub = sigPub,
                encAlg = "RSA", encKeyAlg = "RSA-OAEP-256", encAeadAlg = "A256GCM",
                encPriv = encPriv, encPub = encPub,
            ))
        }
    }

    @Nested
    @DisplayName("Nested JWE: EdDSA signing + EC encryption")
    inner class NestedJweEdEc {
        @Test
        fun `nested JWE with Ed25519 signing and EC P-384 encryption`() {
            val (sigPriv, sigPub) = eddsaKeyPair("Ed25519")
            val (encPriv, encPub) = ecKeyPair("secp384r1")
            roundTrip(config(
                TokenFormat.NESTED_JWE,
                sigAlg = "Ed25519", sigSigAlg = "EdDSA", sigPriv = sigPriv, sigPub = sigPub,
                encAlg = "EC", encKeyAlg = "ECDH-ES+A256KW", encAeadAlg = "A192CBC-HS384",
                encPriv = encPriv, encPub = encPub,
            ))
        }
    }

    private fun config(
        format: TokenFormat,
        sigAlg: String = "EC",
        sigSigAlg: String? = null,
        sigPriv: String? = null,
        sigPub: String? = null,
        encAlg: String = "EC",
        encKeyAlg: String = "ECDH-ES+A256KW",
        encAeadAlg: String = "A192CBC-HS384",
        encPriv: String? = null,
        encPub: String? = null,
    ): AuthNConfig = AuthNConfig(
        mode = AuthMode.STANDALONE,
        jwt = JwtConfig(
            issuer = ISSUER,
            tokenFormat = format,
            signing = SigningConfig(
                algorithm = sigAlg,
                signatureAlgorithm = sigSigAlg,
                encodedPrivateKey = sigPriv,
                encodedPublicKey = sigPub,
            ),
            encryption = EncryptionConfig(
                algorithm = encAlg,
                keyAlgorithm = encKeyAlg,
                aeadAlgorithm = encAeadAlg,
                encodedPublicKey = encPub,
                encodedPrivateKey = encPriv,
            ),
            expiration = ExpirationConfig(
                tokenMinutes = 525_9600,
                refreshTokenMinutes = 525_9600,
            ),
        ),
    )
}
