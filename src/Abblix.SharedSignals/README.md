# Abblix.SharedSignals

The [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) for .NET: transmitter and receiver in one package, built over [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents). A transmitter tells its receivers that something security-relevant happened to a shared subject - a session revoked, a credential compromised - and this package carries both ends of that conversation: the event streams, their management API, and delivery over push (RFC 8935) and poll (RFC 8936).

## What is inside

The transmitter side:

- The configuration document served at `/.well-known/ssf-configuration`, which is how a receiver finds every other endpoint.
- Stream management per SSF 1.0 Section 8.1: create, read, update, replace and delete streams, read and change stream status, add and remove subjects, request verification events.
- `EventDispatcher`, the one call a host makes when something happens: it fans the event out to every stream whose subject and event type match, mints a signed Security Event Token per stream, and enqueues it for that stream's delivery method.
- Delivery: `PushDeliverySender` drains a stream's queue into the receiver's endpoint (RFC 8935), and the poll endpoint serves and acknowledges queued events (RFC 8936).
- Stores behind small interfaces: `IStreamStore` holds stream state, `IEventOutbox` holds minted-but-undelivered tokens. Defaults ship in the package; see the storage section below.

The receiver side:

- `TransmitterConfigurationClient` discovers a transmitter, `StreamManagementClient` drives its management API, `PollClient` fetches and acknowledges events.
- A push intake that runs the full validation pipeline of Abblix.SecurityEvents - signature, issuer, audience, typ, replay - and hands each verified event to the host's `ISecurityEventSink`, exactly once per event.

The endpoints themselves are mapped by the ASP.NET Core adapter package, [Abblix.SharedSignals.MinimalApi](https://www.nuget.org/packages/Abblix.SharedSignals.MinimalApi); this package is host-framework-neutral.

## Install

```bash
dotnet add package Abblix.SharedSignals
```

## A transmitter

```csharp
builder.Services.AddSecurityEvents(options =>
    options.SigningKeySource = _ => ValueTask.FromResult(signingKey));

builder.Services.AddSsfTransmitter(new SsfTransmitterOptions
{
    Issuer = "https://issuer.example.com",
    EventsSupported = [CaepEventTypes.SessionRevoked],
    PollEndpointFactory = streamId => new Uri($"https://issuer.example.com/ssf/poll/{streamId}"),
});
```

When a session actually ends, one call reaches every receiver that subscribed to it:

```csharp
await dispatcher.DispatchAsync(new SecurityEventDescriptor
{
    EventType = CaepEventTypes.SessionRevoked,
    Subject = new ComplexSubject { Session = new OpaqueSubject(sessionId), User = userSubject },
    Payload = new SessionRevokedPayload { InitiatingEntity = CaepEventPayload.InitiatingEntities.Policy },
});
```

## A receiver

```csharp
builder.Services.AddSecurityEvents(options => options.Events.RegisterCaepEvents());
builder.Services.AddJwksKeyResolution(options =>
    options.JwksUriSelector = issuer => transmitterMetadata.JwksUri);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddDistributedReplayCache();
builder.Services.AddSsfReceiver(new SsfValidationOptions
{
    ExpectedAudience = "https://receiver.example.com",
    ExpectedIssuers = ["https://issuer.example.com"],
});
builder.Services.AddSingleton<ISecurityEventSink, MySink>();
```

The sink is where the host reacts - terminate the local session, force a credential reset - and the pipeline guarantees each event reaches it verified and only once, however many times the transmitter redelivers.

## Storage

Stream state and the outbox are deliberately separate tiers:

- Streams can live in configuration: `ConfigurationStreamStore` reads declared streams from `appsettings.json`, which suits a closed deployment where the receivers are known - nothing to back up, nothing to migrate.
- The outbox holds events between minting and delivery. The in-package `DistributedCacheEventOutbox` is correct for a single transmitter instance; a transmitter running replicas takes [Abblix.SharedSignals.Redis](https://www.nuget.org/packages/Abblix.SharedSignals.Redis), whose server-side atomic operations survive concurrency. Losing the outbox loses pending events, and the protocols budget for that (SSF 1.0 Section 8.1.2.1) - the queue belongs beside caches, not beside data that earns backups.

## Event dictionaries

The framework carries events; their vocabularies ship as separate dictionary packages registered over the same event registry: [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP) for session and access lifecycle, [Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC) for account risk incidents, and any host-defined events via `EventTypeRegistry.Register`.

## License

Abblix.SharedSignals is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
