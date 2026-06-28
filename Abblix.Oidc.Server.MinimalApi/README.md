# Abblix OIDC Server — Minimal API integration

This package maps the Abblix OpenID Connect / OAuth 2.0 server endpoints as ASP.NET Core **Minimal API** route handlers. It offers the same protocol coverage as `Abblix.OIDC.Server.MVC` without taking a dependency on the MVC framework.

Both packages sit on top of the framework-neutral core (`Abblix.Oidc.Server`) and differ only in the transport layer.

## Quick start

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

`MapOidcEndpoints()` maps all endpoints onto a route group and returns the `RouteGroupBuilder`, so cross-cutting conventions can be applied to all OIDC endpoints at once:

```csharp
app.MapOidcEndpoints()
    .RequireRateLimiting("oidc");
```

An optional prefix mounts every endpoint under a sub-path:

```csharp
app.MapOidcEndpoints(prefix: "/auth"); // e.g. /auth/connect/token, /auth/.well-known/jwks
```

Endpoints that allow cross-origin requests (checksession, token, revoke, userinfo, endsession) carry CORS metadata, so a host that enables them registers a CORS policy named `OidcConstants.CorsPolicyName` and calls `app.UseCors()`.

## Endpoint enablement and routes

- Each endpoint is mapped only when its flag is set in `OidcOptions.EnabledEndpoints`; a disabled endpoint is never registered and returns 404.
- Route templates default to `/connect/*` and `/.well-known/*` and are overridable through `OidcRouteOptions`.

For full documentation, see <https://docs.abblix.com>.
