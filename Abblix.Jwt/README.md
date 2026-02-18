# Abblix JWT

**Abblix.JWT** provides complete JWT signing, encryption, validation, and management built entirely on .NET cryptographic primitives and `System.Text.Json.Nodes`. It implements [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) (JWE), and [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) (JWA) with a JWT-optimized architecture that eliminates the `Microsoft.IdentityModel.Tokens` dependency.

## What's New in Version 2.2

- **Custom JWT Implementation**: Complete signing/encryption infrastructure using `System.Text.Json.Nodes` and .NET crypto primitives (`RSA`, `ECDsa`, `AES`) directly — no `Microsoft.IdentityModel.Tokens` dependency
- **Enhanced JWE Algorithms**: `RSA-OAEP-256` (SHA-256), AES-GCM key wrapping (`A128GCMKW`/`A192GCMKW`/`A256GCMKW`), and direct key agreement (`dir`) per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- **Operation Capability Validation**: `JsonWebKey` classes now validate key operations (sign, verify, encrypt, decrypt) before use
- **Interoperability Verified**: Bidirectional tests with `Microsoft.IdentityModel.Tokens` confirm full compatibility across unsigned JWTs, all signing algorithms, and JWE encryption combinations

## Key Features

- **Signing Algorithms**: RSA (RS256/RS384/RS512, PS256/PS384/PS512), ECDSA (ES256/ES384/ES512), HMAC (HS256/HS384/HS512)
- **Encryption Algorithms**: RSA-OAEP, RSA-OAEP-256, AES-GCM key wrapping (A128GCMKW/A192GCMKW/A256GCMKW), direct key agreement (dir)
- **Content Encryption**: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- **Native JSON Types**: `JsonObject`-based programming model handles numbers, arrays, and nested objects without string conversions
- **Exception-Free Validation**: Try pattern throughout the validation pipeline for better performance
- **JWK Management**: Full JSON Web Key lifecycle with operation capability checks

## Implemented Standards

- **JSON Web Signature (JWS)**: [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- **JSON Web Encryption (JWE)**: [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- **JSON Web Key (JWK)**: [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- **JSON Web Algorithms (JWA)**: [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- **JSON Web Token (JWT)**: [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Installation

```bash
dotnet add package Abblix.JWT
```

## Part of the Abblix OIDC Server Ecosystem

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | Advanced .NET DI extensions with aliasing, composites, and decorators |
| **Abblix.JWT** | JWT signing, encryption, and validation *(this package)* |
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET MVC integration for OIDC server |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
