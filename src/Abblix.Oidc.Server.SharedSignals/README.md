# Abblix.OIDC.Server.SharedSignals

Runs an [Abblix Shared Signals](https://www.nuget.org/packages/Abblix.SharedSignals) transmitter on an Abblix OIDC Server, so that each tenant transmits as itself.

Each tenant of the server is an issuer of its own, and a transmitter answering for all of them alike would let one tenant's receivers see another's streams and receive events signed in the name of the wrong issuer. This package keeps them apart:

- each tenant's streams, queued events and delivery claims are kept apart from the others' in whatever stores the transmitter uses, so two tenants may declare a stream under the same receiver and stream identifiers;
- the issuer, the key set address and the endpoint addresses a tenant's receivers see are that tenant's, and follow it when it moves to another issuer;
- every security event token is signed with the keys of the tenant it is transmitted for;
- push delivery runs for each tenant the server serves, in turn;
- once a running instance releases a tenant, at least one refresh period after the tenant left the store of tenants, its streams and the events queued on them are deleted, and a stream that cannot be deleted is logged. A tenant that left the store while no instance served it, as during a restart, is not released by the instances that start afterwards, so its streams stay.

## Turning it on

Register the transmitter and the stores it uses first, then the server and the transmitter's part in it:

```csharp
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.Consents;
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

// Grants every client everything it asks for, which suits only clients of your own;
// to ask the end user for consent, register your own IUserConsentsProvider instead
builder.Services.AddConsentGrantedForEveryClient();

builder.Services
    .AddOidcServices(options => options.Tenants.Add(new TenantDefinition
    {
        Id = "acme",
        Issuer = new Uri("https://idp.example.com/acme"),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    }))
    .AddSharedSignals();
```

The transmitter's issuer names the host without a path. Each tenant's addresses take their paths from the options and put them under the tenant's issuer: for a tenant whose issuer is `https://idp.example.com/acme`, the configuration document is served at `https://idp.example.com/.well-known/ssf-configuration/acme` and its key set address is `https://idp.example.com/acme/.well-known/jwks`.

Each tenant has a transmitter of its own, and what your code resolves from the container - the event dispatcher, the stream store, the stream management service - is the part of the transmitter of the tenant served when it is resolved. Resolve it in the request, or inside `TenantScope.Enter`, that the event belongs to; a part kept across requests keeps answering as the tenant it was resolved for, and one resolved where no tenant is served refuses once it is used.

A request that reaches no tenant is answered 404. A receiver is accepted only with credentials the tenant's own issuer issued: the issuer is read from the `iss` claim the host's authentication leaves behind, or through `ReceiverIssuerSelector` of `SharedSignalsEndpointOptions` where the host keeps it elsewhere. So a receiver of one tenant cannot reach another tenant's streams by presenting its credentials under that tenant's address, even with the same identifier.

A tenant can declare its streams in configuration instead of letting its receivers create them. The declared streams are that tenant's stream set, and only its receivers find them:

```csharp
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SharedSignals.Transmitter;

builder.Services
    .AddOidcServices(options => options.Tenants.Add(acme))
    .AddSharedSignals()
    .AddConfiguredStreams("acme", builder.Configuration.GetSection("Acme:Streams").Get<ConfiguredStream[]>() ?? []);
```

The server does not start when the stream store, the transmitter's identity or its delivery pass has been replaced after `AddSharedSignals()`, when the transmitter's issuer names a path or its key set address is on another host, or when streams are declared for the whole server with `AddSharedSignalsConfiguredStreams`, since those belong to no tenant's receivers.
