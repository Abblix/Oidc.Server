# Abblix OIDC Server MVC

**Abblix.OIDC.Server.MVC** integrates the Abblix OIDC Server with ASP.NET Core MVC, providing controller classes, model binding, and routing for the OpenID Connect endpoints. This is the recommended package for controller-based ASP.NET Core applications; hosts without MVC take [Abblix.OIDC.Server.MinimalAPI](https://www.nuget.org/packages/Abblix.OIDC.Server.MinimalAPI) instead.

## What's New in Version 2.4

✏️ Improvements
- Referencing both transport adapters is refused at startup with a message naming which package to drop, instead of every OIDC request failing with `AmbiguousMatchException` once the new Minimal API sibling joins the dependency graph

## Key Features

- Standard MVC Integration: Uses ASP.NET controller classes, model binding, and attribute routing - no custom middleware required
- OIDC Endpoint Controllers: Authorization, token, userinfo, introspection, revocation, device authorization, and more
- Session Management: Check session iframe and RP-initiated logout with CSP nonce support
- Front-Channel & Back-Channel Logout: Complete logout notification via both channels
- Discovery Endpoint: Auto-configured `/.well-known/openid-configuration` metadata
- Dynamic Client Registration: REST API for client management per RFC 7591/7592
- Host-owned interactive pages: login and consent stay in your application - MVC, Razor Pages or anything else - while the package serves the protocol endpoints

## Install

```bash
dotnet add package Abblix.OIDC.Server.MVC
```

This package includes **Abblix.OIDC.Server**, **Abblix.JWT**, **Abblix.DependencyInjection**, and **Abblix.Utils** as transitive dependencies.

## Quick Start

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOidcServices(options =>
{
    options.Clients = new[] { /* client configurations */ };
    options.Scopes = new[] { /* scope definitions */ };
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
```

## Endpoint URLs

A host that needs an OIDC endpoint's URL - to point an external identity provider's callback back at the authorization endpoint, say - asks `IOidcEndpointResolver`:

```csharp
var authorizationUrl = resolver.Resolve(OidcEndpoints.Authorize);
```

Both transport adapters register it, so this code is written once and survives a change of adapter; an endpoint the host does not serve resolves to `null`.

## Implemented Standards

This package provides ASP.NET Core MVC endpoints for the full suite of standards implemented by the Abblix OIDC Server core, including:

- OAuth 2.0: Authorization Code, Implicit, Client Credentials, Device Authorization ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)), PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)), PAR ([RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)), JAR ([RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101)), DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))
- OpenID Connect: Core 1.0, Discovery, Dynamic Client Registration, Session Management, RP-Initiated/Front-Channel/Back-Channel Logout, CIBA
- JWT: JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), JWE ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)), JWT Access Tokens ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068))

For the complete standards list, see the [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) package documentation.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | .NET DI extensions with aliasing, composites, and decorators |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **Abblix.OIDC.Server.MVC** | ASP.NET Core MVC integration *(this package)* |
| **[Abblix.OIDC.Server.MinimalAPI](https://www.nuget.org/packages/Abblix.OIDC.Server.MinimalAPI)** | ASP.NET Core Minimal API integration |
| **[Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents)** | Security Event Tokens (RFC 8417) and Subject Identifiers (RFC 9493): building, validation, and the delivery data types |
| **[Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals)** | OpenID Shared Signals Framework 1.0 transmitter and receiver |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

Abblix.OIDC.Server.MVC is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
