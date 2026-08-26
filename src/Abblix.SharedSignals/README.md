# Abblix.SharedSignals

The [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) for .NET: transmitter and receiver in one package, built on [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents). A transmitter tells its receivers that something security-relevant happened to a shared subject - a session revoked, a credential compromised - and this package carries both ends of that conversation: the event streams, their management API, and delivery over push (RFC 8935) and poll (RFC 8936).

[Shared Signals in .NET: SSF, CAEP, RISC and Back-Channel Logout](https://www.abblix.com/en/docs/shared-signals-framework) explains what streams are for: the management questions OIDC client registration answered for Back-Channel Logout, and that nothing answers outside it.

## What is inside

The transmitter side:

- The configuration document served at `/.well-known/ssf-configuration`, which is how a receiver finds every other endpoint.
- Stream management per SSF 1.0 Section 8.1: create, read, update, replace and delete streams, read and change stream status, add and remove subjects, request verification events.
- `EventDispatcher`, the one call a host makes when something happens: it fans the event out to every stream whose subject and event type match, mints a signed Security Event Token per stream, and enqueues it for that stream's delivery method.
- Delivery: `PushDeliverySender` drains a stream's queue into the receiver's endpoint (RFC 8935), and the poll endpoint serves and acknowledges queued events (RFC 8936).
- Stores behind small interfaces: `IStreamStore` holds stream state, `IEventOutbox` holds minted-but-undelivered tokens. Defaults ship in the package; see the storage section below.

The receiver side:

- `TransmitterConfigurationClient` discovers a transmitter at the address its issuer resolves to, with an explicit-address overload for transmitters that publish the document elsewhere - the issuer identity check binds either way. `StreamManagementClient` drives the management API, `PollClient` fetches and acknowledges events - transport only, so a poll-based receiver runs the validation profile and the sink itself.
- A push intake that runs the full validation profile of Abblix.SecurityEvents - typ, `exp` absence, events, the REQUIRED `jti`, issuer, signature, audience, `iat` freshness - and hands each accepted event to the host's `ISecurityEventSink`. Duplicate suppression rides alongside the profile: the opt-in replay cache is consulted after the verdict, so a rejected token can never burn an identifier.

The endpoints themselves are mapped by the ASP.NET Core adapter package, [Abblix.SharedSignals.MinimalAPI](https://www.nuget.org/packages/Abblix.SharedSignals.MinimalAPI); this package is host-framework-neutral.

## Install

```bash
dotnet add package Abblix.SharedSignals
dotnet add package Abblix.SecurityEvents.CAEP   # the samples below use the CAEP event dictionary
```

## A transmitter

```csharp
builder.Services.AddSecurityEvents(options =>
    options.SigningKeySource = _ => Task.FromResult(signingKey));

builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
{
    Issuer = "https://issuer.example.com",
    EventsSupported = [CaepEventTypes.SessionRevoked],
    PollEndpointFactory = streamId => new Uri($"https://issuer.example.com/ssf/poll/{streamId}"),
});
```

Two things the configuration document says about that deployment come from defaults rather than from the
snippet above, and both are worth knowing before it goes anywhere real.

`authorization_schemes` is published as OAuth 2.0 unless you set it. The CAEP Interoperability Profile
requires that value to be there, and it is a claim about how your Stream Management API is authorized -
so if yours is authorized by something else, mutual TLS for instance, set `AuthorizationSchemes` to your
own list, or to an empty list to advertise none at all.

`JwksUri` has no default and no way to have one, because only you know where your JWK Set is published.
Without it a receiver cannot obtain a key and cannot verify a single event. Shared Signals Framework 1.0
requires the member of any transmitter that signs, which this one always does, so leave it unset only
while you are still wiring things up. Both gaps are logged once, when the routes are mapped.

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
builder.Services.AddJwksKeyResolution();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddDistributedReplayCache();
builder.Services.AddSharedSignalsReceiver(new SharedSignalsValidationOptions
{
    ExpectedAudience = "https://receiver.example.com",
    ExpectedIssuers = ["https://issuer.example.com"],
});
builder.Services.AddSingleton<ISecurityEventSink, MySink>();
```

A receiver learns where the transmitter's keys are from the transmitter, so that pair is recorded once the configuration document has been read rather than while the host is composed:

```csharp
var transmitter = await transmitterConfigurationClient.GetAsync(issuer, cancellationToken);
jwksOptions.CurrentValue.AddSharedSignalsJwksUri(transmitter);
```

`AddSharedSignalsJwksUri` refuses a document advertising no `jwks_uri` and names the transmitter, because every SET is signed: falling through to the guessed `{issuer}/.well-known/jwks.json` would answer an unverifiable transmitter with a wrong document rather than with a failure anybody can act on. Several transmitters are several calls, and none displaces another.

The sink is where the host reacts - terminate the local session, force a credential reset - and the push pipeline hands it only events that passed the full validation profile, the REQUIRED `jti` included, so every accepted event is trackable.

Duplicate suppression is a separate opt-in tier: register `AddDistributedReplayCache()` backed by a cache shared by every receiver instance, and the pipeline skips a redelivery whose `jti` it has already seen. The underlying add-if-absent is probabilistic rather than strict, and RFC 8935 Section 2 lets a transmitter redeliver regardless of earlier responses - so write the sink to be idempotent and treat duplicate suppression as the second line, not the first. Where strictness is wanted anyway, `ReplayCacheBase` supplies the same contract over a conditional write the deployment's own store performs.

## Storage

Stream state and the outbox are deliberately separate tiers, and both default to in-memory stores (`InMemoryStreamStore`, `InMemoryEventOutbox`):

- Streams can live in configuration: `AddSharedSignalsConfiguredStreams` accepts streams the host declares - `Configuration.GetSection("...").Get<IReadOnlyList<ConfiguredStream>>()` binds them straight from `appsettings.json` - which suits a closed deployment where the receivers are known: nothing to back up or migrate. The binding is the host's on purpose, so the section name stays its choice and the same declarations can come from environment variables, a database or code instead. Two things own such a stream and the store keeps them apart. The **file** owns what the stream is - receiver, identifier, audiences, events, delivery endpoint, subjects mode - and is written over the store at every start, so editing configuration reaches the deployment. The **receiver** owns what it has since done through the management API - the status it set, the subjects it added and removed, when it last asked for verification - and that is carried over rather than rebuilt. A stream the file no longer declares is dropped, because here the file is the stream set. How far the receiver's half reaches is the backing store's doing: in memory by default, and `AddSharedSignalsRedisConfiguredStreams` for a transmitter running replicas, without which a pause is honoured only by the instance that took the request.
- The outbox holds events between minting and delivery. `AddSharedSignalsDistributedOutbox()` moves it onto the host's `IDistributedCache` - correct for a single transmitter instance; a transmitter running replicas takes [Abblix.SharedSignals.Redis](https://www.nuget.org/packages/Abblix.SharedSignals.Redis), whose server-side transactions survive concurrency. Losing the outbox loses pending events, and the protocol tolerates that: SSF 1.0 Section 8.1.2.1 lets a transmitter drop events held for a paused stream, and neither delivery RFC requires durable queues - so the queue belongs beside caches, the tier that earns no backups.
- Push delivery runs on a timer in every instance, so a stream is claimed before it is swept and only the holder delivers it. The default claim, `ProcessLocalDeliveryLease`, reaches inside one process: right for a single instance, and believed by every replica once there are several. A transmitter running replicas takes `AddSharedSignalsRedisDeliveryLease()` from the same Redis package. The transmitter names the claim's implementation in its startup log, so which one a deployment wired is readable rather than assumed.

## Event dictionaries

The framework carries events; their vocabularies ship as separate dictionary packages registered in the same event registry: [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP) for session and access lifecycle, [Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC) for account risk incidents, and any host-defined events via `options.Events.Register`.

## Part of the Abblix product family

Abblix.SharedSignals sits on [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents), which owns the token and the wire. Its ASP.NET Core routes come from [Abblix.SharedSignals.MinimalAPI](https://www.nuget.org/packages/Abblix.SharedSignals.MinimalAPI) and its replica-safe outbox from [Abblix.SharedSignals.Redis](https://www.nuget.org/packages/Abblix.SharedSignals.Redis). The identity provider these signals originate from is [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

## License

Abblix.SharedSignals is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
