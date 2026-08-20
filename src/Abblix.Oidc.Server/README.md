# Abblix OIDC Server

**Abblix OIDC Server** is a .NET library implementing the server side of OpenID Connect and OAuth 2.0: a certified provider you embed in your own ASP.NET Core application instead of running a separate identity product. It is certified by the OpenID Foundation across all login and logout profiles, builds on the standard .NET DI container, and uses its own JWT implementation built on .NET cryptographic primitives.

## What's New in Version 2.4

🚀 **Features**
- **Minimal API integration**: every OIDC endpoint as ASP.NET Core route handlers via the new [Abblix.OIDC.Server.MinimalAPI](https://www.nuget.org/packages/Abblix.OIDC.Server.MinimalAPI) package, with full protocol parity with the MVC integration
- **External signing keys**: private keys held in HashiCorp Vault / OpenBao Transit ([Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)) or Azure Key Vault ([Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)) - the private halves never enter the process, the public halves publish to the JWKS endpoint
- **Security events and Shared Signals**: a new package family implementing Security Event Tokens ([RFC 8417](https://datatracker.ietf.org/doc/html/rfc8417)) with Subject Identifiers ([RFC 9493](https://datatracker.ietf.org/doc/html/rfc9493)), push and poll SET delivery ([RFC 8935](https://datatracker.ietf.org/doc/html/rfc8935), [RFC 8936](https://datatracker.ietf.org/doc/html/rfc8936)), the OpenID Shared Signals Framework 1.0 in both transmitter and receiver roles, and the CAEP 1.0 and RISC 1.0 event dictionaries

## What's New in Version 2.3

🚀 **Features**
- **Rich Authorization Requests ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396))**: fine-grained, transaction-level authorization details across the authorization endpoint, PAR, the token endpoint, CIBA, and the device grant
- **Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))**: impersonation and delegation with multiple subject- and actor-token formats
- **DPoP sender-constrained tokens ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))**: signature-based proof of possession for public clients that cannot use mTLS
- **Certificate-bound access token verification ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) §3)**: resource-server check that a presented token matches the client certificate
- **JARM**: signed, optionally encrypted JWT authorization responses
- **JWT-secured token introspection ([RFC 9701](https://datatracker.ietf.org/doc/html/rfc9701))**: signed introspection responses via content negotiation
- **JWE-encrypted request objects ([RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101))**: confidential request parameters in the front channel and by reference
- **Signed authorization server metadata ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414))**: opt-in, integrity-protected discovery document

✏️ **Improvements**
- Secure-by-default: Implicit Flow is now opt-in, and Dynamic Client Registration requires an Initial Access Token ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591))
- Token-class confusion defense via opt-in token-type pinning ([RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)), JWS key pinned to its declared algorithm ([RFC 8725 §3.1](https://datatracker.ietf.org/doc/html/rfc8725)), enforced HMAC key length ([RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518))
- Authorization-response issuer parameter ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)) advertised in discovery

## Implemented Standards

Abblix OIDC Server implements the following standards for authorization and security:

### OAuth 2.0
- **The OAuth 2.0 Authorization Framework**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **Bearer Token Usage**: [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750), **HTTP Authentication**: [RFC 9110, Section 11](https://datatracker.ietf.org/doc/html/rfc9110#section-11)
- **Token Revocation**: [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)
- **Token Introspection**: [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)
- **Proof Key for Code Exchange (PKCE)**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- **Device Authorization Grant**: [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- **Dynamic Client Registration**: [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) and [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592)
- **Mutual-TLS Client Authentication**: [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)
- **Demonstrating Proof of Possession (DPoP)**: [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- **Resource Indicators**: [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)
- **JWT Access Tokens**: [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)
- **JWT-Secured Authorization Request (JAR)**: [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101)
- **Pushed Authorization Requests (PAR)**: [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)
- **Authorization Server Issuer Identification**: [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)
- **Multiple Response Types**: [Specification](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- **Form Post Response Mode**: [Specification](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)

### JSON Web Token (JWT)
- **JWS**: [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), **JWE**: [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516), **JWK**: [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517), **JWA**: [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518), **JWT**: [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- **JWT Client Authentication**: [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)
- **Authentication Method Reference Values**: [RFC 8176](https://datatracker.ietf.org/doc/html/rfc8176)

### OpenID Connect
- **Core 1.0**: [Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- **Discovery 1.0 / Authorization Server Metadata**: [Specification](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)
- **Dynamic Client Registration 1.0**: [Specification](https://openid.net/specs/openid-connect-registration-1_0.html)
- **Session Management 1.0**: [Specification](https://openid.net/specs/openid-connect-session-1_0.html)
- **RP-Initiated Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- **Front-Channel Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- **Back-Channel Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- **Client-Initiated Backchannel Authentication (CIBA)**: [Specification](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
- **Pairwise Pseudonymous Identifiers (PPID)**: [OpenID Connect Core Section 8](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)

## Install

```bash
dotnet add package Abblix.OIDC.Server
```

> **Note**: Most applications should use [Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC) or [Abblix.OIDC.Server.MinimalAPI](https://www.nuget.org/packages/Abblix.OIDC.Server.MinimalAPI), which include this package plus the ASP.NET Core endpoint wiring.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | .NET DI extensions with aliasing, composites, and decorators |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **[Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)** | Signing and decryption keys held in HashiCorp Vault / OpenBao Transit |
| **[Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)** | Signing and decryption keys held in Azure Key Vault |
| **Abblix.OIDC.Server** | Core OpenID Connect server implementation *(this package)* |
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET Core MVC integration |
| **[Abblix.OIDC.Server.MinimalAPI](https://www.nuget.org/packages/Abblix.OIDC.Server.MinimalAPI)** | ASP.NET Core Minimal API integration |
| **[Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents)** | Security Event Tokens (RFC 8417) and Subject Identifiers (RFC 9493): building, validation, and the delivery data types |
| **[Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP)** | The CAEP 1.0 event dictionary: session and access lifecycle |
| **[Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC)** | The RISC 1.0 event dictionary: account risk incidents |
| **[Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals)** | OpenID Shared Signals Framework 1.0 transmitter and receiver |
| **[Abblix.SharedSignals.MinimalAPI](https://www.nuget.org/packages/Abblix.SharedSignals.MinimalAPI)** | SSF endpoints as ASP.NET Core Minimal API route handlers |
| **[Abblix.SharedSignals.Redis](https://www.nuget.org/packages/Abblix.SharedSignals.Redis)** | Redis-native event outbox for multi-replica transmitters |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

Abblix.OIDC.Server is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
