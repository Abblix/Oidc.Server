# Abblix.SharedSignals.MinimalApi

ASP.NET Core Minimal API integration for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): the OpenID Shared Signals Framework 1.0 endpoints as route handlers, with no MVC dependency.

## Install

```bash
dotnet add package Abblix.SharedSignals.MinimalApi
```

## Transmitter

```csharp
builder.Services
    .AddSecurityEvents(options => options.SigningKeySource = ...)
    .AddSsfTransmitter(new SsfTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        JwksUri = new Uri("https://tr.example.com/.well-known/jwks.json"),
    });

var app = builder.Build();
app.MapSsfTransmitterEndpoints("/ssf").RequireAuthorization("ssf-receivers");
```

One call maps the whole management surface under the prefix - streams, status, subjects, verification, poll delivery - plus the configuration document at the well-known address the issuer resolves to.

The well-known endpoint stays outside the returned group on purpose: discovery must answer before any receiver has credentials, so the authorization you attach to the group does not cover it. What it serves is public metadata - issuer, JWKS location, endpoint addresses, supported delivery methods and authorization schemes - and nothing stream- or receiver-specific; poll delivery sits inside the group, which is where SSF 1.0 Section 7.1.1 wants it.

A gateway-fronted deployment adjusts this without moving the protocol address: `MapSsfTransmitterEndpoints(prefix, mapWellKnownConfiguration: false)` leaves the canonical route to the gateway or CDN in front, and `MapSsfConfigurationDocument(advertisedPrefix, pattern)` serves the same document on an internal route a rewriting proxy maps the canonical address onto - advertising the external prefix, whatever was mapped internally. The external address never moves, because receivers derive it from the issuer.

Receivers are told apart by identity: the endpoints read it from the authenticated principal (the `sub` claim, then the identity name), and `SsfEndpointOptions.ReceiverIdSelector` replaces that mapping when the host's authentication carries the identity elsewhere.

What one call maps, relative to the prefix:

| Route | Method | SSF 1.0 |
|---|---|---|
| `/stream` | POST, GET, PATCH, PUT, DELETE | stream management, Section 8.1.1 |
| `/status` | GET, POST | stream status, Section 8.1.2 |
| `/subjects:add`, `/subjects:remove` | POST | subject management, Section 8.1.3 |
| `/verify` | POST | verification request, Section 8.1.4 |
| `/poll/{streamId}` | POST | poll delivery, RFC 8936 |

The configuration document at `/.well-known/ssf-configuration` advertises the five management addresses from the very constants that map them, so those cannot drift; the well-known path itself follows the specification, not the prefix, because that fixed address is how a receiver holding only the issuer URI finds everything else. The poll address is the one exception: it travels per stream and comes from your `PollEndpointFactory`, so keep that factory aligned with the prefix you pass here.

## Receiver

```csharp
builder.Services
    .AddSecurityEvents()
    .AddJwksKeyResolution()
    .AddDistributedMemoryCache()   // or Redis - the replay cache rides the host's IDistributedCache
    .AddDistributedReplayCache()
    .AddSsfReceiver(new SsfValidationOptions
    {
        ExpectedAudience = "https://receiver.example.com",
        ExpectedIssuers = ["https://tr.example.com"],
        StreamIssuer = "https://tr.example.com",
    })
    .AddSingleton<ISecurityEventSink, MyEventSink>();

var app = builder.Build();
app.MapSsfPushEndpoint("/events")
    .RequireAuthorization("ssf-transmitters");
```

The push endpoint answers the empty 202 or the 400 whose body speaks the RFC 8935 registry vocabulary; where accepted events land is the host's `ISecurityEventSink`.

Signature validation decides whether an event is genuine, but it is not what keeps the endpoint standing: an unauthenticated route spends a cryptographic verification on every body posted to it, which RFC 8935 Section 5.4 names as the recipient's denial-of-service exposure and answers with transmitter authentication and rate limiting. Attach both - the returned builder takes the host's conventions like any other route.

## License

Abblix.SharedSignals.MinimalApi is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
