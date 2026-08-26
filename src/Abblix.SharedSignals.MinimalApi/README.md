# Abblix.SharedSignals.MinimalAPI

ASP.NET Core Minimal API integration for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): the OpenID Shared Signals Framework 1.0 endpoints as route handlers, with no MVC dependency.

[Shared Signals in .NET: SSF, CAEP, RISC and Back-Channel Logout](https://www.abblix.com/en/docs/shared-signals-framework) explains which endpoints belong to the event layer and which to the stream layer, so the two adapters stop looking interchangeable.

## Which adapter maps which endpoint

There are two Minimal API packages in this family, and the line between them is not the one that first suggests itself. It is **not** transmitter here and receiver there: this package holds receiver-role code of its own - the stream management client, the transmitter discovery client. The question that decides placement is whether the endpoint stops making sense **without a stream**:

- **Stream management, status, subjects, verification, the `ssf-configuration` document, and the transmitter's poll endpoint** - every one is meaningless without a stream, and the poll address is addressed *by stream identifier*. Here.
- **Push delivery intake** - "accept a SET at this address" (RFC 8935 Section 2.1). The URL is the receiver's own and carries no stream identity, so a receiver can be handed events by a counterparty known from anywhere. That endpoint is `MapPushDeliveryEndpoint` in [Abblix.SecurityEvents.MinimalAPI](https://www.nuget.org/packages/Abblix.SecurityEvents.MinimalAPI), which a push-based receiver installs alongside this one: the dependency chain here reaches the core library but not the core's adapter.
- **Back-Channel Logout** - one token, delivered once, from a provider the relying party already knows. Also there.

Push and poll are the pair worth understanding, because both are core delivery specifications (RFC 8935 and RFC 8936) and yet they land in different packages. What separates them is not which document defines the protocol but whether a stream is part of the addressing: the push intake just accepts a token, while the poll endpoint below serves one stream's queue and is addressed per stream. The specification says how to carry an event; the stream says to whom - and that second half is what this package is.

The split is kept for what it buys the other side: a relying party that wants only Back-Channel Logout takes the core adapter alone, and never sees this package's surface.

## Install

```bash
dotnet add package Abblix.SharedSignals.MinimalAPI
dotnet add package Abblix.SecurityEvents.MinimalAPI   # a push-based receiver also needs the intake endpoint
```

## Transmitter

```csharp
builder.Services
    .AddSecurityEvents(options => options.SigningKeySource = ...)
    .AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        JwksUri = new Uri("https://tr.example.com/.well-known/jwks.json"),
    });

var app = builder.Build();
app.MapSharedSignalsTransmitterEndpoints().RequireAuthorization("ssf-receivers");
```

One call maps the whole management surface under `SharedSignalsEndpointOptions.ManagementPrefix` (`/ssf` by default) - streams, status, subjects, verification, poll delivery - plus the configuration document at the well-known address the issuer resolves to. Every route comes from the options, so one object states the whole topology.

The well-known endpoint stays outside the returned group on purpose: discovery must answer before any receiver has credentials, so the authorization you attach to the group does not cover it. What it serves is public metadata - issuer, JWKS location, endpoint addresses, supported delivery methods and authorization schemes - and nothing stream- or receiver-specific; poll delivery sits inside the group, which is where SSF 1.0 Section 7.1.1 wants it.

Two members of that metadata come from defaults. `authorization_schemes` is published as OAuth 2.0 unless you set it - the CAEP Interoperability Profile requires that value, and it is a claim about how your management surface is authorized, so a deployment using something else should set `AuthorizationSchemes` to its own list or to an empty list to advertise none. `jwks_uri` has no default, because only you know where your JWK Set is published, and without it no receiver can verify an event. Both absences are logged once when the routes are mapped.

A gateway-fronted deployment adjusts this in the same options object, without moving the protocol address: `MapWellKnownConfiguration = false` leaves the canonical route to the gateway or CDN in front, `ConfigurationDocumentRoute` names the internal route a rewriting proxy maps the canonical address onto (served by `MapSharedSignalsConfigurationDocument()`), and `AdvertisedPrefix` is what the document advertises - the external prefix, whatever `ManagementPrefix` mapped internally. The external address never moves, because receivers derive it from the issuer.

Receivers are told apart by identity: the endpoints read it from the authenticated principal (the `sub` claim, then the identity name), and `SharedSignalsEndpointOptions.ReceiverIdSelector` replaces that mapping when the host's authentication carries the identity elsewhere.

Scopes are the other half, and they are off until you switch them on. The CAEP Interoperability Profile defines `ssf.read` and `ssf.manage` and requires a transmitter to check that a token is sufficient for what was asked. It assigns five operations: reading a stream's configuration and getting its status to `ssf.read`, creating a stream, deleting one and verification to `ssf.manage`. The other six routes it does not assign, and this library places them - everything that changes a stream needs `ssf.manage`, and poll needs `ssf.read`. Note what that last one costs: a poll acknowledges, acknowledging releases the transmitter from retaining those events, so `ssf.read` is enough to empty a queue - and while a stream is looked up by the caller's identity, the queue behind it is keyed by stream id alone, so two receivers naming one stream share it. Each route knows which scope it needs, but this package never sees a token, so it cannot find the granted scopes on its own:

```csharp
builder.Services.AddSingleton(new SharedSignalsEndpointOptions
{
    GrantedScopesSelector = ctx => ctx.User.FindFirst("scope")?.Value.Split(' ') ?? [],
});
```

Set it and a caller whose token is too narrow gets 403 with `insufficient_scope` and the scope it needs to ask for. A caller nothing identified still gets the bare 401 instead - not having authenticated is not a scope problem. Leave the selector unset and no scope is checked at all, which is what this surface did before the option existed: a working deployment, and one outside the profile. Your authorization server has to be able to grant the two scope values; this library's own refuses any scope nobody registered with it.

What one call maps, relative to the prefix:

| Route | Method | SSF 1.0 |
|---|---|---|
| `/stream` | POST, GET, PATCH, PUT, DELETE | stream management, Section 8.1.1 |
| `/status` | GET, POST | stream status, Section 8.1.2 |
| `/subjects:add`, `/subjects:remove` | POST | subject management, Section 8.1.3 |
| `/verify` | POST | verification request, Section 8.1.4 |
| `/poll/{streamId}` | POST | poll delivery, RFC 8936 |

The configuration document at `/.well-known/ssf-configuration` advertises the five management addresses from the very constants that map them, so those cannot drift; the well-known path itself follows the specification, not the prefix, because that fixed address is how a receiver holding only the issuer URI finds everything else. The poll address travels per stream rather than in the document, and it comes from the same prefix, so a stream's `endpoint_url` leads back to the route serving it whatever you set the prefix to. A proxy that rewrites paths needs nothing extra: what the mapping declares is `AdvertisedPrefix`, so the poll address follows it along with the five above. `PollEndpointFactory` is for the address that prefix cannot describe - delivery on a separate host name, say - and it wins.

## Receiver

```csharp
builder.Services
    .AddSecurityEvents()
    .AddJwksKeyResolution()
    .AddDistributedMemoryCache()   // or Redis - the replay cache rides the host's IDistributedCache
    .AddDistributedReplayCache()
    .AddSharedSignalsReceiver(new SharedSignalsValidationOptions
    {
        ExpectedAudience = "https://receiver.example.com",
        ExpectedIssuers = ["https://tr.example.com"],
        StreamIssuer = "https://tr.example.com",
    })
    .AddSingleton<ISecurityEventSink, MyEventSink>();

var app = builder.Build();
app.MapPushDeliveryEndpoint("/events")
    .RequireAuthorization("ssf-transmitters");
```

The intake endpoint itself comes from `Abblix.SecurityEvents.MinimalAPI`, which this package already depends on - see the section above for why RFC 8935's intake belongs to the core while the poll endpoint above belongs here. It answers the empty 202 or the 400 whose body speaks the RFC 8935 registry vocabulary; where accepted events land is the host's `ISecurityEventSink`.

Signature validation decides whether an event is genuine, but it is not what keeps the endpoint standing: an unauthenticated route spends a cryptographic verification on every body posted to it, which RFC 8935 Section 5.4 names as the recipient's denial-of-service exposure and answers with transmitter authentication and rate limiting. Attach both - the returned builder takes the host's conventions like any other route.

## Part of the Abblix product family

Abblix.SharedSignals.MinimalAPI maps the routes of [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals), which in turn sits on [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents). The identity provider these signals originate from is [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

## License

Abblix.SharedSignals.MinimalAPI is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
