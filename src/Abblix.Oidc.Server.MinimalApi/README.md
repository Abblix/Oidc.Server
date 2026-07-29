# Abblix OIDC Server Minimal API

**Abblix.OIDC.Server.MinimalApi** integrates the Abblix OIDC Server with ASP.NET Core **Minimal APIs**, mapping the OpenID Connect and OAuth 2.0 endpoints as route handlers. It offers the same protocol coverage as `Abblix.OIDC.Server.MVC` without taking a dependency on the MVC framework. Both packages sit on top of the framework-neutral core (`Abblix.OIDC.Server`) and differ only in the transport layer.

## What's New in Version 2.4

🚀 **Features**
- **Minimal API integration**: maps every OIDC endpoint as an ASP.NET Core route handler via `AddOidcMinimalApi` and `MapOidcEndpoints`, with full feature parity with the MVC integration - JARM authorization responses, JWT-secured token introspection ([RFC 9701](https://datatracker.ietf.org/doc/html/rfc9701)), and request binding for Rich Authorization Requests ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)) and Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))

## Key Features

- **MVC-free Integration**: maps OIDC endpoints as Minimal API route handlers - no controllers, no `Microsoft.AspNetCore.Mvc` dependency
- **OIDC Endpoints**: authorization, token, userinfo, introspection, revocation, device authorization, pushed authorization requests, and more
- **Single Route Group**: `MapOidcEndpoints()` returns the `RouteGroupBuilder`, so cross-cutting conventions (rate limiting, auth, filters) apply to all OIDC endpoints at once
- **Endpoint Enablement**: each endpoint is mapped only when its flag is set in `OidcOptions.EnabledEndpoints`; a disabled endpoint is never registered and returns 404
- **Configurable Routes & Prefix**: route templates default to `/connect/*` and `/.well-known/*`, overridable via `OidcRouteOptions`, with an optional path prefix
- **CORS-aware**: cross-origin endpoints (checksession, token, revoke, userinfo, endsession) carry CORS metadata for the `OidcConstants.CorsPolicyName` policy
- **Discovery Endpoint**: auto-configured `/.well-known/openid-configuration` metadata
- **Dynamic Client Registration**: REST API for client management per RFC 7591/7592

## Installation

```bash
dotnet add package Abblix.OIDC.Server.MinimalApi
```

This package includes **Abblix.OIDC.Server**, **Abblix.JWT**, **Abblix.DependencyInjection**, and **Abblix.Utils** as transitive dependencies.

## Quick Start

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOidcMinimalApi(options =>
{
    // configure issuer, clients, signing keys, enabled endpoints, ...
});

var app = builder.Build();

app.MapOidcEndpoints();

app.Run();
```

`MapOidcEndpoints()` maps all enabled endpoints onto a route group and returns the `RouteGroupBuilder`, so cross-cutting conventions can be applied to all OIDC endpoints at once:

```csharp
app.MapOidcEndpoints()
    .RequireRateLimiting("oidc");
```

An optional prefix mounts every endpoint under a sub-path:

```csharp
app.MapOidcEndpoints(prefix: "/auth"); // e.g. /auth/connect/token, /auth/.well-known/jwks
```

Endpoints that allow cross-origin requests (checksession, token, revoke, userinfo, endsession) carry CORS metadata, so a host that enables them registers a CORS policy named `OidcConstants.CorsPolicyName` and calls `app.UseCors()`.

## Migrating from the MVC integration

**Remove the `Abblix.OIDC.Server.MVC` package reference.** Referencing it is enough for its controllers to be mapped: `AddControllers()` finds controller assemblies in the dependency graph on its own, whether or not `AddOidcServices()` was ever called. With both packages in place the two transports claim the same paths and every OIDC request fails with `AmbiguousMatchException`. `MapOidcEndpoints()` refuses to start an application in that state and says which package to drop.

The rest of the swap: call `AddOidcMinimalApi` in place of `AddOidcServices`, `app.MapOidcEndpoints()` in place of `app.MapControllers()`, and rename any response formatter the host replaced or decorated - the interfaces are named `...ResultFormatter` here and return `IResult` instead of `ActionResult`.

## Endpoint URLs

A host that needs an OIDC endpoint's URL - to point an external identity provider's callback back at the authorization endpoint, say - asks `IOidcEndpointResolver`:

```csharp
var authorizationUrl = resolver.Resolve(OidcEndpoints.Authorize);
```

Both integrations register it, so this code is written once and survives a change of adapter. The answer comes from the endpoints as mapped, so a route override or a `MapOidcEndpoints(prefix)` prefix is already in it, and an endpoint the host does not serve resolves to `null`.

## Implemented Standards

This package provides ASP.NET Core Minimal API endpoints for the full suite of standards implemented by the Abblix OIDC Server core, including:

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
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET MVC integration for OIDC server |
| **Abblix.OIDC.Server.MinimalApi** | ASP.NET Core Minimal API integration for OIDC server *(this package)* |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **General inquiries**: [info@abblix.com](mailto:info@abblix.com)
- **Support and security reports**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
