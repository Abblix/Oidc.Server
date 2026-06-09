# Abblix OIDC Server MVC

**Abblix.OIDC.Server.MVC** integrates the Abblix OIDC Server with ASP.NET MVC, providing controller classes, model binding, and routing mechanisms for seamless OpenID Connect integration. This is the recommended package for adding OIDC-based authentication and authorization to ASP.NET WebApi and MVC applications.

## What's New in Version 2.3

🚀 **Features**
- **JARM**: MVC support for signed, optionally encrypted JWT authorization responses
- **JWT-secured token introspection ([RFC 9701](https://datatracker.ietf.org/doc/html/rfc9701))**: content-negotiated signed introspection responses

✏️ **Improvements**
- Request binding for **Rich Authorization Requests ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396))** and **Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))**

## Key Features

- **Standard MVC Integration**: Uses ASP.NET controller classes, model binding, and attribute routing — no custom middleware required
- **OIDC Endpoint Controllers**: Authorization, token, userinfo, introspection, revocation, device authorization, and more
- **Session Management**: Check session iframe and RP-initiated logout with CSP nonce support
- **Front-Channel & Back-Channel Logout**: Complete logout notification via both channels
- **Discovery Endpoint**: Auto-configured `/.well-known/openid-configuration` metadata
- **Dynamic Client Registration**: REST API for client management per RFC 7591/7592
- **Razor Template Rendering**: Customizable HTML pages for interactive OIDC flows

## Installation

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

## Implemented Standards

This package provides ASP.NET MVC endpoints for the full suite of standards implemented by the Abblix OIDC Server core, including:

- **OAuth 2.0**: Authorization Code, Implicit, Client Credentials, Device Authorization ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)), PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)), PAR ([RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)), JAR ([RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101)), DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))
- **OpenID Connect**: Core 1.0, Discovery, Dynamic Client Registration, Session Management, RP-Initiated/Front-Channel/Back-Channel Logout, CIBA
- **JWT**: JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), JWE ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)), JWT Access Tokens ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068))

For the complete standards list, see the [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) package documentation.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | Advanced .NET DI extensions with aliasing, composites, and decorators |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **Abblix.OIDC.Server.MVC** | ASP.NET MVC integration for OIDC server *(this package)* |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
