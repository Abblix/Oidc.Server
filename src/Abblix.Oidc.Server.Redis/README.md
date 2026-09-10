# Abblix.OIDC.Server.Redis

Take-once redemption on Redis for [Abblix OIDC Server](https://www.nuget.org/packages/Abblix.OIDC.Server). An authorization code, a device code and a CIBA request id each stand for an authorization that may be redeemed once, and this package is what makes that true when the provider runs as more than one instance.

## The problem it solves

Deciding a redemption over a plain distributed cache is not possible: a read, a write and a delete are separate operations, so any protocol built from them leaves a window where a second caller either wins as well or the value is destroyed with nobody told it won. Issuing two token sets for one authorization code is the failure the whole arrangement exists to prevent, and [RFC 6749 section 4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2) requires the server to deny a reused code rather than answer it twice.

The server already serializes redemptions of one key inside its own process. That settles the question for a single instance and says nothing about several, which is where this package comes in: Redis decides, in one command, who redeemed.

## Install

```
dotnet add package Abblix.OIDC.Server.Redis
```

## Use

```csharp
services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect("localhost:6379"));

services.AddRedisTakeOnceStore();
services.AddOidcServices(options => { ... });
```

The connection is the host's, and a deployment already using Redis for its distributed cache has one. Nothing else changes: the storages ask this store when it is registered and keep their previous behaviour when it is not.

## How the take is done

`GETDEL` returns the value to exactly one caller and deletes it, in one command, on Redis 6.2 and later. Where the command is absent the same two lines run as a script, which Redis executes with nothing interleaved, so both paths carry the same guarantee.

Which path applies is not read off a version string, because a cluster can run mixed versions and a version answers for one node. The command is attempted, and the script becomes the instance's path once it has been seen to take where the command was refused. A server merely too busy for one take is therefore not mistaken for one that lacks the command.

## Part of the Abblix product family

This package sits on [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server), which owns the protocol. A transmitter of security events that needs the same replica-safety for its own queue uses [Abblix.SharedSignals.Redis](https://www.nuget.org/packages/Abblix.SharedSignals.Redis).

## License

See LICENSE.md in the package, and [the licensing page](https://www.abblix.com/abblix-oidc-server) for what each edition allows.

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
