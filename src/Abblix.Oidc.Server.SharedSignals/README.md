# Abblix.Oidc.Server.SharedSignals

Runs an [Abblix Shared Signals](https://www.nuget.org/packages/Abblix.SharedSignals) transmitter on a multi-tenant Abblix OIDC Server, so that each tenant transmits as itself.

Under multi-tenancy each tenant of the server is an issuer of its own, and a transmitter answering for all of them alike would let one tenant's receivers see another's streams and receive events signed in the name of the wrong issuer. This package keeps them apart:

- each tenant's streams are kept apart from the others' in whatever store the transmitter uses, and its queued events are reached only through those streams;
- the issuer, the key set address and the endpoint addresses a tenant's receivers see are that tenant's;
- every security event token is signed with the keys of the tenant serving the request;
- push delivery runs for each tenant the server serves, in turn.

## Turning it on

Register the transmitter and the stores it uses first, then turn on multi-tenancy and the transmitter's part in it:

```csharp
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSecurityEvents();
builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
{
    Issuer = "https://idp.example.com",
    JwksUri = new Uri("https://idp.example.com/.well-known/jwks"),
    EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
});

builder.Services.AddOidcServices(_ => { });
builder.Services
    .AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
    {
        Id = "acme",
        Issuer = "https://idp.example.com/acme",
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    }))
    .AddSharedSignals();
```

Multi-tenancy is experimental, so the compiler reports `ABXMT001` on these calls until the project suppresses it, for example with `<NoWarn>$(NoWarn);ABXMT001</NoWarn>`.

The transmitter's issuer names the host without a path. Each tenant's addresses take their paths from the options and put them under the tenant's issuer: for a tenant whose issuer is `https://idp.example.com/acme`, the configuration document is served at `https://idp.example.com/.well-known/ssf-configuration/acme` and its key set address is `https://idp.example.com/acme/.well-known/jwks`.

A request that reaches no tenant is answered 404. A receiver is accepted only with credentials the tenant's own issuer issued: the issuer is read from the `iss` claim the host's authentication leaves behind, or through `ReceiverIssuerSelector` of `SharedSignalsEndpointOptions` where the host keeps it elsewhere. So a receiver of one tenant cannot reach another tenant's streams by presenting its credentials under that tenant's address, even with the same identifier.

The server does not start when the stream store, the transmitter's identity or its delivery pass has been replaced after `AddSharedSignals()`, when the transmitter's issuer names a path or its key set address is on another host, or when streams are declared in configuration, since declared streams belong to no tenant.
