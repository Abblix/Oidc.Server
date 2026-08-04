# Abblix.SharedSignals.Redis

The Redis-native event outbox for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): each stream's queue on Redis list and hash structures, every mutation a server-side transaction over keys that share one cluster hash tag. Take this package the day the transmitter scales past one replica.

## Install

```bash
dotnet add package Abblix.SharedSignals.Redis
```

## Why native structures

The in-package distributed-cache outbox stores each queue as one value, so its mutations are read-modify-write - correct for a single transmitter instance serializing them in-process, and silently lossy the day the transmitter scales to replicas: one replica's enqueue overwrites another's. This outbox appends, removes by value and deletes fields on the server, inside a transaction, so concurrent replicas compose instead of overwriting each other.

What that buys is that no enqueue or acknowledgement is lost; what it does not buy is single delivery, because a delivery pass reads and then acknowledges rather than leasing - two replicas draining one stream can send the same SET twice. RFC 8935 Section 2 lets a transmitter redeliver regardless, and the receiver's replay cache is where that is absorbed.

## Usage

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

builder.Services
    .AddSecurityEvents(...)
    .AddSsfTransmitter(...)
    .AddSsfRedisOutbox();
```

The queue and item keys of one stream share a cluster hash tag, so the outbox works unchanged under Redis Cluster. Losing Redis loses pending events - the tier is deliberate: SSF 1.0 Section 8.1.2.1 lets a transmitter drop events held for a paused stream, and neither delivery RFC requires durable queues, so the queue belongs beside caches, the tier that earns no backups.

## License

Abblix.SharedSignals.Redis is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
