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

## Hardening built in

The validation pipeline enforces what the specifications say a careless implementation forgets: a key that declares an `alg` is never used for another algorithm when producing or verifying a JWS ([RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) Section 3.1; JWE key unwrapping selects by `kid` and the header's `alg`, so a decryption key's declared `alg` is not a filter there). An HMAC key shorter than its hash output is rejected (RFC 7518 Section 3.2), and a `crit` header names only parameters a registered handler understands - an unhandled critical parameter rejects the token, on the JWE envelope as on the JWS (RFC 7515 Section 4.1.11).

## External keys

Signing and decryption do not require the private key to live in the process: the custodian seam delegates the cryptographic operation to an external holder - `AddVaultCustodian` for HashiCorp Vault / OpenBao ([Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)), `AddAzureCustodian` for Azure Key Vault ([Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)), both built on this package's `AddKeyCustodian`.

## Implemented standards

- JSON Web Signature (JWS): [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- JSON Web Encryption (JWE): [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- JSON Web Key (JWK): [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- JWK Thumbprint: [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)
- JSON Web Algorithms (JWA): [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- JSON Web Token (JWT): [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- AES Key Wrap: [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394)

## Part of the Abblix family

Abblix.JWT is the token layer under [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) and [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents); the full family lives in the [repository](https://github.com/Abblix/Oidc.Server).

## License

Abblix.JWT is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
