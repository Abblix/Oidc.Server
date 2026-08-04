# Abblix.Utils

The foundation layer of the Abblix packages: the small, dependency-light pieces that security-focused code keeps needing - careful URI construction, log sanitization, cryptographic encodings, JSON converters for wire formats, and a Result type for expected failures. Every other Abblix package builds on it; it is equally usable on its own.

## Install

```bash
dotnet add package Abblix.Utils
```

## What is inside

### URIs and parameters

`UriBuilder`, `UriExtensions` and `ParametersBuilder` construct and take apart URIs with explicit control over query and fragment parts - the difference that matters when a redirect URI must carry a response exactly where the protocol says, and nowhere else.

### Result: expected failures as values

`Result<TSuccess, TFailure>` models an operation whose failure is an expected outcome rather than an exception - validation, protocol errors, lookups that legitimately find nothing. Both outcomes are values, `Match` and the `MapSuccess`/`MapFailure` combinators compose them railway-style, and `TryGetSuccess`/`TryGetFailure` unwrap at the edges:

```csharp
Result<AuthorizedGrant, AuthError> result = await AuthorizeAsync(request);
return result.Match(RenderTokens, RenderError);
```

### Log sanitization

`Sanitized` wraps a value for logging so control characters cannot forge log lines. Anything a caller sent - identifiers, URIs, header values - goes through it before reaching a log template:

```csharp
logger.LogWarning("Unknown client {ClientId}", new Sanitized(clientId));
```

### Cryptographic encodings and randomness

`CryptoRandom` produces cryptographically strong random material for tokens and identifiers. `Base32` and `HexConverter` cover the encodings certificates and secrets travel in, and `CertificateId` with `ICertificateProvider` abstract certificate lookup.

### JSON converters for wire formats

Custom `System.Text.Json` converters for the shapes protocol messages actually use: unix-seconds timestamps (`DateTimeOffsetUnixTimeSecondsConverter`), durations as integer seconds (`TimeSpanSecondsConverter`), space-separated lists such as OAuth scopes (`SpaceSeparatedValuesConverter`), values that arrive as either a single item or an array (`SingleOrArrayConverter`), base64url binary (`Base64UrlTextEncoderConverter`), and null-dropping serialization (`JsonIgnoreNullsAttribute`).

### Distributed cache helpers

`DistributedCacheExtensions` adds the operation `IDistributedCache` lacks for security bookkeeping: `TryAddAsync`, an add-if-absent that makes single-use semantics - replay caches, one-time codes - expressible over any cache backend.

### Collections and enums

`ArrayExtensions`, `EnumerableExtensions`, `EnumFlagExtensions` and `ObjectExtensions` carry the small operations that otherwise get re-implemented per project.

## Part of the Abblix family

Abblix.Utils sits under [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT), [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server), [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents) and the rest of the family; the full set lives in the [repository](https://github.com/Abblix/Oidc.Server).

## License

Abblix.Utils is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
