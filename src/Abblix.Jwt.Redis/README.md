# Abblix.JWT.Redis

Redis-native replay prevention for [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT) and [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server). A single-use token's identifier is reserved with one conditional write on the server, so a second presentation is refused outright rather than probabilistically. Take this package the day the deployment runs more than one instance and a profile depends on that refusal.

## Install

```bash
dotnet add package Abblix.JWT.Redis
```

## Why a package rather than a class

`StackExchange.Redis` cannot go into `Abblix.JWT` without landing on every consumer of it, so a separate assembly is forced whatever else one thinks. The name says which boundary it is: the **Redis adapter for the JWT layer**, not "the replay cache package" - anything else in that layer that comes to need a Redis backing belongs here too.

It sits beside `Abblix.SharedSignals.Redis` rather than inside it, and the direction is not a matter of taste. Nothing here consumes Shared Signals, while the contract's callers are the OIDC server's DPoP proofs and client authenticators and the Security Events receiver. Folding it in would make a host that wants strict replay protection for DPoP take the whole Shared Signals stack to get it.

## Why a second implementation

`IReplayCache` asks for a reservation and an answer in one call, and it always has - the contract does not change here, because only an implementation can promise that the two are indivisible.

The shipped `DistributedReplayCache` rides the host's `IDistributedCache`, which offers Get and Set and no compare-and-set. Its reservation is therefore read-then-write, and two presenters of one identifier inside a single cache round trip can both be told the token is fresh. That is not a defect of that class: the interface it stands on cannot express the fix.

This one is `SET key value NX PX ttl`. The condition is evaluated by the server inside the command that writes, so no caller can be between the two, and it makes no difference how many instances of the application asked or whether they asked at the same instant.

Which profiles were content without strictness is worth knowing, because it decides whether you need this package:

- **DPoP proofs** - RFC 9449 Section 11.1 accepts probabilistic replay defence explicitly.
- **Security Event Tokens** - RFC 8935 Section 2 lets a transmitter redeliver a SET regardless of earlier responses, so a lost race costs one duplicate pass over a sink that had to be idempotent anyway.
- **Client assertions** - the one that does not read that way. RFC 7523 Section 3 lets an authorization server reject a reused assertion, and a deployment relying on that rejection is relying on strictness.

## Usage

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

builder.Services.AddRedisReplayCache();
```

Register the **interface**, not the concrete multiplexer: the cache takes `IConnectionMultiplexer`, and handing over the concrete type leaves it unresolvable until something resolves the graph.

The call uses `Replace`, so it wins whichever order it runs in relative to the registration supplying the distributed-cache default - `AddOidcCore`, `AddSecurityEvents` and the Shared Signals roles each offer one, and a host cannot control the order of a registration that happens inside another call. The contract is singular, so the one implementation serves DPoP proofs, client assertions and Security Event Tokens alike; that is safe because a profile whose identifier is unique only within a scope composes the scope into the value it reserves.

## The key prefix

Reservations live under `Abblix.Jwt:ReplayPrevention:` unless the call names another:

```csharp
builder.Services.AddRedisReplayCache("my-app:replay:");
```

Treat the value as a deployment contract once chosen. Entries written under one prefix are invisible under another, so changing it mid-rollout leaves what the previous instances reserved unreachable - and during that window a token they refused passes as fresh at the new ones, until the old entries age out.

A lifetime that has already elapsed is floored to a few seconds rather than refused. A caller's clock can legitimately be behind, and the client rejects a non-positive expiry before the command leaves the process - so without the floor the reservation would throw, and a caller reading that as "not seen before" would accept every replay a skewed clock presented.

## License

Abblix.JWT.Redis is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
