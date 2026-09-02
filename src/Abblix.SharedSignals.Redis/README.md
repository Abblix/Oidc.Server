# Abblix.SharedSignals.Redis

The Redis-native transmitter storage for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): the event outbox and the stream registry: each stream's queue on Redis list and hash structures, every mutation a server-side transaction over keys that share one cluster hash tag. Take this package the day the transmitter scales past one replica.

[Shared Signals in .NET: SSF, CAEP, RISC and Back-Channel Logout](https://www.abblix.com/en/docs/shared-signals-framework) covers what running a transmitter on more than one instance actually requires, and which of the shipped defaults are single-instance by design.

## Install

```bash
dotnet add package Abblix.SharedSignals.Redis
```

## Why native structures

The in-package distributed-cache outbox stores each queue as one value, so its mutations are read-modify-write - correct for a single transmitter instance serializing them in-process, and silently lossy the day the transmitter scales to replicas: one replica's enqueue overwrites another's. This outbox appends, removes by value and deletes fields on the server, inside a transaction, so concurrent replicas compose instead of overwriting each other.

Composing mutations is one half. The other is single delivery, and it is a separate call: `AddSharedSignalsRedisDeliveryLease()`. A delivery pass reads a stream's queue and acknowledges what the receiver takes, so without a claim every replica reads the same pending SETs and every one of them POSTs them - N transmissions of each event, by construction rather than occasionally.

RFC 8935 Section 2 permits redelivery ("The SET Transmitter MAY transmit the same SET to the SET Recipient multiple times, regardless of the response"), but the same section binds the transmitter the other way: it "SHOULD NOT retransmit a SET" outside a suspected recoverable failure, and should delay retransmission "to avoid overwhelming the SET Recipient". Replicas duplicating each other's work suspect nothing, so that is the SHOULD NOT rather than a matter of traffic.

## Usage

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

builder.Services
    .AddSecurityEvents(...)
    .AddSharedSignalsTransmitter(...)
    .AddSharedSignalsRedisOutbox();
```

The queue and item keys of one stream share a cluster hash tag, so the outbox works unchanged under Redis Cluster. The receiver and the stream are both escaped before they are joined into that tag. That is what keeps a closing brace out of it whatever an identifier is called - one inside the tag ends it early, and one at its very start empties it, which would put a stream's two keys on different slots - and it is also what decides where the join splits, since the separator cannot occur inside either half. So no identifier is refused for its spelling. An empty receiver or stream is refused, as any missing argument is.

A queue expires after `RedisOutboxOptions.Retention` without a new event, seven days by default. The clock measures inactivity, so a stream still receiving events never reaches it, and only the queue of a departed receiver is reclaimed. Losing Redis loses pending events - the tier is deliberate, and it is a decision rather than a permission: SSF 1.0 Section 8.1.2.1 lets a transmitter drop events held while a stream is paused, and requires transmission for an enabled one. Neither delivery RFC requires durable queues, so the queue belongs beside caches, the tier that earns no backups.

## Stream registrations

`AddSharedSignalsRedisStreamStore()` puts the transmitter's stream registrations on one Redis hash - the durable `IStreamStore` for a transmitter whose streams must outlive its process without a database of its own.

```csharp
builder.Services
    .AddSecurityEvents(...)
    .AddSharedSignalsTransmitter(...)
    .AddSharedSignalsRedisOutbox()
    .AddSharedSignalsRedisStreamStore();
```

The key carries the transmitter's own issuer, so two deployments sharing one Redis keep separate registries; without that they would read each other's streams and deliver their own signed events to each other's receivers.

## Streams declared in configuration

`AddSharedSignalsRedisConfiguredStreams(streams)` is the configuration-declared stream set with its runtime half in Redis, for a closed deployment that also runs replicas.

The host does the binding, which is why the call takes the declarations rather than an `IConfiguration`: the section's name is the host's to choose, and the declarations can equally come from environment variables, a database or code.

```csharp
var streams = builder.Configuration.GetSection("SharedSignals:Streams").Get<IReadOnlyList<ConfiguredStream>>()
    ?? throw new InvalidOperationException("The 'SharedSignals:Streams' configuration section is missing.");

builder.Services
    .AddSecurityEvents(...)
    .AddSharedSignalsTransmitter(...)
    .AddSharedSignalsRedisConfiguredStreams(streams);
```

A missing section binds to null rather than to an empty set, and the two mean opposite things - "nobody configured this" against "this transmitter serves nobody" - so refuse it at startup instead of starting a transmitter with no receivers and no complaint. What the binder cannot check for you is a member left out of a stream that IS declared: `required` is a compile-time rule and binding ignores it, so an omitted `ReceiverId` arrives as null. That one the store refuses itself, naming the position in the section.

At startup each declaration is written over what Redis holds and the receiver's own half is carried across: the status it set, the subjects it added and removed, and when it last asked for verification. So editing the file reaches every instance at its next start, while a pause a receiver asked for reaches them all at once - where the in-package version honours it only in the instance that took the request.

The subjects are the part worth naming. Under `SubjectsMode.None` the subjects a receiver added ARE the stream's coverage, so rebuilding the state from the file - the obvious reading of "configuration is truth" - would unsubscribe that receiver from everything it subscribed to, and SSF 1.0 Section 9.1 tells it a success says nothing about the transmitter's state, so it never asks and never finds out.

A stream Redis holds that the file no longer declares is dropped: here the file is the stream set, and keeping it would go on delivering security events to a receiver the operator removed.

## Single delivery across replicas

`AddSharedSignalsRedisDeliveryLease()` is what makes several replicas a division of the streams rather than N copies of the work. Before sweeping a stream a replica claims it with a write conditional on the key not existing - the one Redis primitive that can decide between askers sharing nothing else - and a replica told no passes that stream by and takes one the others have not reached.

```csharp
builder.Services
    .AddSecurityEvents(...)
    .AddSharedSignalsTransmitter(...)
    .AddSharedSignalsRedisOutbox()
    .AddSharedSignalsRedisStreamStore()
    .AddSharedSignalsRedisDeliveryLease();
```

Without this call the claim is `ProcessLocalDeliveryLease`, which reaches inside one process and no further, so every replica believes it holds every stream. The transmitter names the implementation in its startup log for exactly that reason - a deployment can read which one it wired.

The claim expires, because expiry is the only release a replica that died mid-pass can perform, and that makes `SharedSignalsTransmitterOptions.PushDeliveryLeaseDuration` two limits at once: the claim's life and the longest one pass may run. A pass reaching the deadline is cut off there, since past it the stream belongs to whoever takes it next; what it did not deliver goes out on a later pass. Both directions are safe - too short redoes work, too long parks a stream after a replica dies - so set it by which one the deployment minds less. The default is one minute.

This is also why the lease is not offered over `IDistributedCache`. That interface writes whole values unconditionally and has no set-if-absent, so a claim built on it would be granted to every replica that asked - a lock everyone holds, behaving exactly like no lock while reading as coordination.

Two properties of the shape are worth knowing before adopting it. The whole registry travels on every dispatched event and lives on one cluster slot, which suits the tens of receivers a transmitter serves and does not suit thousands. And registrations carry the receivers' delivery credentials, so this Redis holds secrets and deserves the protection of one.

Losing Redis loses registrations - deliberately a tier below a database. Stated plainly: the transmitter stops delivering to everybody until each receiver creates its stream again (SSF 1.0 Section 8.1.1.1), and whether a receiver ever does is a property of that receiver rather than of the protocol. A deployment that cannot accept that keeps its registrations in its own database, which is what `IStreamStore` is for.

## Part of the Abblix product family

Abblix.SharedSignals.Redis is the outbox implementation for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals), which in turn sits on [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents). The identity provider these signals originate from is [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
