# Abblix.JWT

A JWT and JOSE toolkit for .NET, built entirely on the platform's cryptographic primitives and `System.Text.Json.Nodes` - no dependency on `Microsoft.IdentityModel.Tokens`. It implements JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), JWE ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)), JWK ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) and JWA ([RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)), and is the token layer behind Abblix OIDC Server, usable on its own.

## Install

```bash
dotnet add package Abblix.JWT
```

## Issue and validate a token

```csharp
services.AddJsonWebTokens();
```

The registration provides `IJsonWebTokenCreator` and `IJsonWebTokenValidator`. Issuing signs the token with the key you pass, and encrypts it when you also pass an encryption key:

```csharp
var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

var jwt = await creator.IssueAsync(
    new JsonWebToken
    {
        Header = { Algorithm = SigningAlgorithms.RS256 },
        Payload =
        {
            Issuer = "https://issuer.example.com",
            Audiences = ["https://api.example.com"],
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
        },
    },
    key);
```

Validation returns a verdict rather than throwing on a bad token: the result is a `Result` carrying either the parsed token or the error naming what failed - malformed input, unknown algorithm, bad signature, unmet issuer or audience policy - and the parameters carry the checks as delegates, so issuer trust and key resolution stay the caller's policy.

Two classes of failure still surface as exceptions, both after the signature has been verified: an `exp`/`nbf` value that is not a number or falls outside `DateTimeOffset`'s range, and a resolved key carrying no public material - wrap the call if your endpoint must answer every input with a protocol error:

```csharp
var result = await validator.ValidateAsync(jwt, new ValidationParameters
{
    ValidateIssuer = issuer => Task.FromResult(issuer == "https://issuer.example.com"),
    ValidateAudience = audiences => Task.FromResult(audiences.Contains("https://api.example.com")),
    ResolveIssuerSigningKeys = issuer => KnownKeysOf(issuer),
});
```

The payload is a `JsonObject` underneath, so claims keep their JSON types - numbers, arrays and nested objects need no string round-trips, and custom claims are first-class.

## Algorithms

- Signing: RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512, HS256/HS384/HS512.
- Key management: RSA-OAEP, RSA-OAEP-256, AES-GCM key wrapping (A128GCMKW/A192GCMKW/A256GCMKW), direct encryption (dir).
- Content encryption: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM.

Two further key-management families ship and stay off until a host asks for them, each because of a
cost the default should not impose. `AddRsaPkcs1KeyManagement()` enables RSA1_5. `AddPbes2KeyManagement()`
enables PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW, where the inbound token's `p2c`
header dictates PBKDF2 work before the token has been authenticated; the iteration count is bounded to
[1000, 10000] even once enabled. Interop with a partner that requires either is one call, not a missing
feature.

## Hardening built in

The validation pipeline enforces what the specifications say a careless implementation forgets: a key that declares an `alg` is never used for another algorithm when producing or verifying a JWS ([RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) Section 3.1; JWE key unwrapping selects by `kid` and the header's `alg`, so a decryption key's declared `alg` is not a filter there). An HMAC key shorter than its hash output is rejected (RFC 7518 Section 3.2), and a `crit` header names only parameters a registered handler understands - an unhandled critical parameter rejects the token, on the JWE envelope as on the JWS (RFC 7515 Section 4.1.11). A host that does understand such a parameter registers a handler for it by name, `AddCriticalHeaderHandler<MyHandler>("my-ext")`: the name is the registration key, so it cannot be claimed without a handler behind it.

## Replay protection

Every JWT profile that forbids replay asks the same question - has this identifier been presented before? - so the primitive lives here rather than in each of them: `IReplayCache` reserves an identifier and answers whether the sighting is the first, in one call, so no caller can read, decide and write in three steps another caller slips between.

```csharp
services.AddSingleton<IReplayCache>(provider =>
    provider.CreateService<DistributedReplayCache>(Dependency.Override("MyApp:ReplayPrevention:")));
```

The shipped implementation stores in the host's `IDistributedCache`, so a single-instance deployment gets process-local behaviour and a scaled-out one gets shared memory by swapping the store. That store offers Get and Set and no compare-and-set, which makes the answer probabilistic within one cache round trip - enough for the profiles that accept it (RFC 9449 Section 11.1 for DPoP proofs, RFC 8935 Section 2 for redelivered Security Event Tokens), and replaceable behind the same interface by a backend-native primitive where it is not.

## External keys

Signing and decryption do not require the private key to live in the process: the custodian seam delegates the cryptographic operation to an external holder - `AddVaultCustodian` for HashiCorp Vault / OpenBao ([Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)), `AddAzureCustodian` for Azure Key Vault ([Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)), `AddCustodian<T>` for one of your own.

Each opens a placement choice you then name, and that is the security posture: `UseKeysInCustodian` keeps every private half outside the process, `UseKeysInProcess` mints keys here and has the custodian only seal them.

The placement calls live in this package, which is what lets a host consume JWTs without being an OpenID Provider and still wire a custodian - no OIDC server anywhere in its graph. A backend package adds the transport for its own vault; with your own custodian this reference is the only one you need:

```csharp
services
    .AddJsonWebTokens()
    .AddCustodian<MyCustodian>()
    .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "sign" });
```

[EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) is the shared model, including what a host without our key provider does to publish the custodian's keys itself.

## Key rings

Keys the host does not supply itself are minted and rotated by a key ring. `AddInMemoryKeyRing(policy)`
keeps them in the process: right for a single instance, and wrong for several, since each replica mints
its own and nothing fails at startup - sign-ins simply break for whoever lands on the wrong replica. So
a host that has registered an `IKeyRingStore`, which is how keys are shared, is refused here rather than
served. `AddKeyRing(policy)` is the shared form: it seals each minted key to the custodian's
key-encryption key and publishes it through that store, which the builder it returns supplies.

What the ring's keys are then used for is the caller's business - an OpenID Provider publishes them at
its JWKS endpoint, another host protects stored sessions with them - which is why the ring lives beside
the key material rather than beside either consumer.

## Implemented standards

- JSON Web Signature (JWS): [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- JSON Web Encryption (JWE): [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- JSON Web Key (JWK): [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- JWK Thumbprint: [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)
- JSON Web Algorithms (JWA): [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- JSON Web Token (JWT): [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- AES Key Wrap: [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394)

## Part of the Abblix product family

Abblix.JWT is the token layer under [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) and [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents); the full family lives in the [repository](https://github.com/Abblix/Oidc.Server).

## License

Abblix.JWT is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
