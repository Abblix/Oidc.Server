# Abblix.SharedSignals.Redis

The Redis-native event outbox for [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals): each stream's queue on Redis list and hash structures, every mutation a server-side atomic operation.

## Why native structures

The in-package distributed-cache outbox stores each queue as one value, so its mutations are read-modify-write - correct for a single transmitter instance serializing them in-process, and silently lossy the day the transmitter scales to replicas. This outbox appends, removes by value and deletes fields on the server itself, so concurrent replicas compose instead of overwriting each other.

## Usage

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

builder.Services
    .AddSecurityEvents(...)
    .AddSsfTransmitter(...)
    .AddSsfRedisOutbox();
```

The queue and item keys of one stream share a cluster hash tag, so the outbox works unchanged under Redis Cluster. Losing Redis loses pending events - the tier is deliberate: the delivery protocols budget for dropped held events (SSF 1.0 Section 8.1.2.1), so the queue belongs beside caches, not beside data that earns backups.

## License

Abblix.SharedSignals.Redis is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
