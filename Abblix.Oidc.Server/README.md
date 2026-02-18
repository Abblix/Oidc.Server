# Abblix OIDC Server

**Abblix OIDC Server** is a robust .NET library that implements the OpenID Connect protocol on the server side. Designed with modular and hexagonal architecture patterns, it provides a compliant, extensible framework for adding OIDC-based authentication and authorization to .NET applications. It supports Dependency Injection using the standard .NET DI container, and uses its own JWT implementation built on .NET cryptographic primitives.

## What's New in Version 2.2

🚀 **Features**
- **Custom JWT Implementation**: Complete JWT signing/encryption infrastructure replacing `Microsoft.IdentityModel.Tokens` — uses `System.Text.Json.Nodes` and .NET crypto primitives directly
- **Enhanced JWE Algorithms**: `RSA-OAEP-256`, AES-GCM key wrapping (`A128GCMKW`/`A192GCMKW`/`A256GCMKW`), and direct key agreement (`dir`)
- **ACR/AMR Compliance (RFC 8176)**: Authentication Context Class Reference values in discovery and RFC 8176 Authentication Method References
- **CSP Nonce Support**: Template-based front-channel logout and check session iframe compatible with strict Content Security Policies

✏️ **Improvements**
- Configurable session cookie path in OIDC Session Management
- Operation capability validation for `JsonWebKey` classes
- Bidirectional interoperability tests with `Microsoft.IdentityModel.Tokens`

## Implemented Standards

Abblix OIDC Server implements a comprehensive suite of standards for authorization and security:

### OAuth 2.0
- **The OAuth 2.0 Authorization Framework**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **Bearer Token Usage**: [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)
- **Token Revocation**: [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)
- **Token Introspection**: [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)
- **Proof Key for Code Exchange (PKCE)**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- **Device Authorization Grant**: [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- **Dynamic Client Registration**: [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) and [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592)
- **Mutual-TLS Client Authentication**: [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)
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

## Installation

```bash
dotnet add package Abblix.OIDC.Server
```

> **Note**: Most applications should use [Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC) which includes this package plus ASP.NET MVC integration with controllers, model binding, and routing.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | Advanced .NET DI extensions with aliasing, composites, and decorators |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **Abblix.OIDC.Server** | Core OpenID Connect server implementation *(this package)* |
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET MVC integration for OIDC server |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
