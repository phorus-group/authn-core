# authn-core

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/group.phorus/authn-core)](https://mvnrepository.com/artifact/group.phorus/authn-core)
[![codecov](https://codecov.io/gh/phorus-group/authn-core/branch/main/graph/badge.svg)](https://codecov.io/gh/phorus-group/authn-core)

Core authentication library for Phorus services. Contains JWT token creation, token validation,
context objects, DTOs, and service interfaces.

### Notes

> The project runs a vulnerability analysis pipeline regularly,
> any found vulnerabilities will be fixed as soon as possible.

> The project dependencies are being regularly updated by [Renovate](https://github.com/phorus-group/renovate).
> Dependency updates that don't break tests will be automatically deployed with an updated patch version.

## Table of contents

- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Quick start](#quick-start)
- [Token formats](#token-formats)
  - [JWS (signed only)](#jws-signed-only)
  - [JWE (encrypted only)](#jwe-encrypted-only)
  - [Nested JWE (signed then encrypted)](#nested-jwe-signed-then-encrypted)
- [Configuration](#configuration)
- [Core implementations](#core-implementations)
  - [TokenCreator](#tokencreator)
  - [StandaloneTokenValidator](#standalonetokenvalidator)
- [Context objects](#context-objects)
  - [AuthContext](#authcontext)
  - [HTTPContext](#httpcontext)
  - [ApiKeyContext](#apikeycontext)
- [DTOs](#dtos)
- [Service interfaces](#service-interfaces)
- [Keys and algorithms](#keys-and-algorithms)
  - [Key type](#key-type)
  - [How token protection works](#how-token-protection-works)
  - [Encryption algorithm reference](#encryption-algorithm-reference)
  - [Configuring and generating keys](#configuring-and-generating-keys)
- [Building and contributing](#building-and-contributing)
- [Authors and acknowledgment](#authors-and-acknowledgment)

***

## Getting started

### Installation

<details open>
<summary>Gradle / Kotlin DSL</summary>

```kotlin
implementation("group.phorus:authn-core:x.y.z")
```
</details>

<details open>
<summary>Maven</summary>

```xml
<dependency>
    <groupId>group.phorus</groupId>
    <artifactId>authn-core</artifactId>
    <version>x.y.z</version>
</dependency>
```
</details>

### Quick start

**1. Generate an EC key pair:**

```bash
openssl ecparam -genkey -name secp384r1 -noout -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out private.der
openssl ec -in key.pem -pubout -outform DER -out public.der
openssl base64 -A -in private.der && echo    # -> encodedPrivateKey
openssl base64 -A -in public.der && echo     # -> encodedPublicKey
rm key.pem private.der public.der
```

**2. Use the keys:**

```kotlin
import group.phorus.authn.core.config.*
import group.phorus.authn.core.services.impl.TokenCreator
import group.phorus.authn.core.services.impl.StandaloneTokenValidator
import java.util.UUID

// 1. Configure
val config = AuthNConfig(
    mode = AuthMode.STANDALONE,
    jwt = JwtConfig(
        issuer = "my-service",
        tokenFormat = TokenFormat.JWS,
        signing = SigningConfig(
            algorithm = "EC",
            encodedPrivateKey = "<base64 PKCS#8 private key>",
            encodedPublicKey = "<base64 X.509 public key>",
        ),
    ),
)

// 2. Create tokens
val tokenCreator = TokenCreator(config)
val accessToken = tokenCreator.createAccessToken(
    userId = UUID.randomUUID(),
    privileges = listOf("read", "write"),
)

// 3. Validate tokens
val validator = StandaloneTokenValidator(config, validators = emptyList())
val authData = validator.authenticate(accessToken.token)
println("User: ${authData.userId}, Privileges: ${authData.privileges}")
```

## Token formats

### JWS (signed only)

Signed-only JWT ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)). Claims are visible
(Base64url-encoded, not encrypted) but tamper-proof. The token has 3 Base64url segments.

```kotlin
val config = AuthNConfig(
    jwt = JwtConfig(
        tokenFormat = TokenFormat.JWS,
        signing = SigningConfig(
            algorithm = "EC",
            encodedPrivateKey = "...",
            encodedPublicKey = "...",
        ),
    ),
)
```

### JWE (encrypted only)

Encrypted-only JWT ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)). Claims are
placed directly in the encrypted payload without an inner signature. The token has 5 Base64url
segments. Provides confidentiality but not independent integrity verification.

```kotlin
val config = AuthNConfig(
    jwt = JwtConfig(
        tokenFormat = TokenFormat.JWE,
        encryption = EncryptionConfig(
            algorithm = "EC",
            keyAlgorithm = "ECDH-ES+A256KW",
            aeadAlgorithm = "A192CBC-HS384",
            encodedPublicKey = "...",
            encodedPrivateKey = "...",
        ),
    ),
)
```

### Nested JWE (signed then encrypted)

Claims are first signed as a JWS, then the JWS is encrypted as the payload of a JWE with
`cty: "JWT"` ([RFC 7516 Appendix A.2](https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2),
[RFC 7519 Section 5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2)). Provides
both integrity and confidentiality.

```kotlin
val config = AuthNConfig(
    jwt = JwtConfig(
        tokenFormat = TokenFormat.NESTED_JWE,
        signing = SigningConfig(
            algorithm = "EC",
            encodedPrivateKey = "...",
            encodedPublicKey = "...",
        ),
        encryption = EncryptionConfig(
            algorithm = "EC",
            keyAlgorithm = "ECDH-ES+A256KW",
            aeadAlgorithm = "A192CBC-HS384",
            encodedPublicKey = "...",
            encodedPrivateKey = "...",
        ),
    ),
)
```

## Configuration

The `AuthNConfig` data class provides all settings needed for token creation and validation:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `mode` | `AuthMode` | `STANDALONE` | Authentication mode |
| `jwt.issuer` | `String?` | `null` | `iss` claim value |
| `jwt.tokenFormat` | `TokenFormat` | `JWS` | Token serialization format |
| `jwt.signing.algorithm` | `String` | `"EC"` | JCA key-factory algorithm |
| `jwt.signing.signatureAlgorithm` | `String?` | `null` | JJWT signature algorithm (auto-detected if null) |
| `jwt.signing.encodedPrivateKey` | `String?` | `null` | Base64 PKCS#8 private key for signing |
| `jwt.signing.encodedPublicKey` | `String?` | `null` | Base64 X.509 public key for verification |
| `jwt.encryption.algorithm` | `String` | `"EC"` | JCA key-factory algorithm |
| `jwt.encryption.keyAlgorithm` | `String` | `"ECDH-ES+A256KW"` | JJWT key-management algorithm |
| `jwt.encryption.aeadAlgorithm` | `String` | `"A192CBC-HS384"` | JJWT content-encryption algorithm |
| `jwt.encryption.encodedPublicKey` | `String?` | `null` | Base64 X.509 public key for encryption |
| `jwt.encryption.encodedPrivateKey` | `String?` | `null` | Base64 PKCS#8 private key for decryption |
| `jwt.expiration.tokenMinutes` | `Long` | `10` | Access token lifetime in minutes |
| `jwt.expiration.refreshTokenMinutes` | `Long` | `1440` | Refresh token lifetime in minutes |

## Core implementations

### TokenCreator

`TokenCreator` implements the `TokenFactory` interface. It creates access and refresh tokens in
the configured format (JWS, JWE, or nested JWE). Pass an `AuthNConfig` to its constructor.

### StandaloneTokenValidator

`StandaloneTokenValidator` implements the `Authenticator` interface. It validates tokens created
by `TokenCreator` (or any standards-compliant JWT library). Token format is auto-detected at parse
time based on the number of Base64url segments:

- 3 segments: JWS (signature verification)
- 5 segments: JWE or nested JWE (decryption, with optional inner signature verification)

It accepts an optional list of `Validator` instances for custom claim validation.

## Context objects

Thread-local holders for request-scoped data. Set them during request processing, read them
from anywhere in the call stack within the same thread.

### AuthContext

```kotlin
// Store
AuthContext.context.set(AuthContextData(userId = user.id, privileges = user.privileges))

// Read
val auth: AuthContextData? = AuthContext.context.get()
```

### HTTPContext

```kotlin
// Store
HTTPContext.context.set(HTTPContextData(path = "/api/users", method = "GET", headers = emptyMap(), queryParams = emptyMap(), remoteAddress = null))

// Read
val http: HTTPContextData? = HTTPContext.context.get()
```

### ApiKeyContext

```kotlin
// Store
ApiKeyContext.context.set(ApiKeyContextData(keyId = "partner-a"))

// Read
val apiKey: ApiKeyContextData? = ApiKeyContext.context.get()
val keyId: String? = apiKey?.keyId
val metadata: Map<String, String> = apiKey?.metadata ?: emptyMap()
```

## DTOs

| Type | Description |
|------|-------------|
| `AuthContextData` | User ID, privilege list, and custom properties from a validated token |
| `AuthData` | Raw token data after parsing: user ID, token type, JTI, privileges |
| `TokenType` | `ACCESS_TOKEN` or `REFRESH_TOKEN` |
| `AccessToken` | Issued token: compact JWT string and its privilege list |
| `HTTPContextData` | Request path, method (as String), headers, query params, timestamps |
| `ApiKeyContextData` | API key identifier and metadata after successful validation |

## Service interfaces

| Interface | Description |
|-----------|-------------|
| `Authenticator` | Validates a compact JWT and returns `AuthData`. Exposes low-level `parseSignedClaims` / `parseEncryptedClaims` for JWS/JWE. |
| `TokenFactory` | Creates signed/encrypted access and refresh tokens. |
| `Validator` | Pluggable claim validator invoked after token parsing. |

Core implementations: `TokenCreator` (implements `TokenFactory`) and `StandaloneTokenValidator`
(implements `Authenticator`).

## Keys and algorithms

### Key type

| Key type | Algorithm value | Signature algorithms | Use case |
|----------|----------------|---------------------|----------|
| EC P-256 | `"EC"` | ES256 | Good default, widely supported |
| EC P-384 | `"EC"` | ES384 (default) | Stronger EC, recommended |
| EC P-521 | `"EC"` | ES512 | Maximum EC security |
| RSA 2048+ | `"RSA"` | RS256, RS384, RS512, PS256, PS384, PS512 | Legacy compatibility |
| Ed25519 | `"Ed25519"` | EdDSA | Modern, fast |
| Ed448 | `"Ed448"` | EdDSA | Stronger EdDSA |

### How token protection works

**JWS (signing):** The private key creates a digital signature over the header and claims. The
public key verifies the signature. Anyone with the public key can verify the token, but only the
private key holder can create valid tokens.

**JWE (encryption):** The public key encrypts the claims. Only the private key can decrypt them.
This hides the claims from anyone without the private key.

**Nested JWE (signing + encryption):** The claims are first signed (JWS), then the entire JWS
is encrypted (JWE). This provides both integrity (signature) and confidentiality (encryption).

### Encryption algorithm reference

**Content encryption (aeadAlgorithm):**

| Algorithm | Key size | Description |
|-----------|----------|-------------|
| `A128CBC-HS256` | 256-bit | AES-CBC + HMAC-SHA-256 |
| `A192CBC-HS384` | 384-bit | AES-CBC + HMAC-SHA-384 (default) |
| `A256CBC-HS512` | 512-bit | AES-CBC + HMAC-SHA-512 |
| `A128GCM` | 128-bit | AES-GCM |
| `A192GCM` | 192-bit | AES-GCM |
| `A256GCM` | 256-bit | AES-GCM |

**Key protection for EC keys (keyAlgorithm):**

| Algorithm | Description |
|-----------|-------------|
| `ECDH-ES` | Direct key agreement |
| `ECDH-ES+A128KW` | Key agreement + AES-128 key wrap |
| `ECDH-ES+A192KW` | Key agreement + AES-192 key wrap |
| `ECDH-ES+A256KW` | Key agreement + AES-256 key wrap (default) |

**Key protection for RSA keys (keyAlgorithm):**

| Algorithm | Description |
|-----------|-------------|
| `RSA-OAEP` | RSA-OAEP (SHA-1) |
| `RSA-OAEP-256` | RSA-OAEP (SHA-256, recommended) |

### Configuring and generating keys

**EC keys (default):**

```bash
# Generate EC P-384 key pair
openssl ecparam -genkey -name secp384r1 -noout -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out private.der
openssl ec -in key.pem -pubout -outform DER -out public.der
openssl base64 -A -in private.der && echo    # -> encodedPrivateKey
openssl base64 -A -in public.der && echo     # -> encodedPublicKey
rm key.pem private.der public.der
```

**RSA keys:**

```bash
# Generate RSA 2048 key pair
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out private.der
openssl pkey -in key.pem -pubout -outform DER -out public.der
openssl base64 -A -in private.der && echo    # -> encodedPrivateKey
openssl base64 -A -in public.der && echo     # -> encodedPublicKey
rm key.pem private.der public.der
```

**EdDSA keys:**

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out private.der
openssl pkey -in key.pem -pubout -outform DER -out public.der
openssl base64 -A -in private.der && echo    # -> encodedPrivateKey
openssl base64 -A -in public.der && echo     # -> encodedPublicKey
rm key.pem private.der public.der
```

## Building and contributing

See [Contributing Guidelines](CONTRIBUTING.md).

## Authors and acknowledgment

Developed and maintained by the [Phorus Group](https://phorus.group) team.
