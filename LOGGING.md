# Logging conventions

All non-test code in this repository emits structured logs through the
[`[LoggerMessage]` source generator](https://learn.microsoft.com/dotnet/core/extensions/logger-message-generator)
on `Microsoft.Extensions.Logging` 8+. New logging code MUST follow the rules
below; ad-hoc `_logger.LogInformation("foo {Bar}", bar)` calls are not allowed.

## Why source generator

- AOT-friendly: zero reflection at the log call site, log methods are emitted
  as strongly typed wrappers at compile time.
- Boxing-free: typed parameters skip `object[]`-style argument promotion.
- Strongly typed: misspelled placeholders fail at compile time, not at runtime.
- Stable EventId: every log entry carries an `EventId` chosen at compile time,
  filterable in the log aggregator without parsing message text.

## EventId allocation

EventId is unique **within a class**, but for log-aggregator filtering we also
allocate non-overlapping numeric ranges per feature area. The canonical
allocation lives in two `internal static class LogEvents` files (one per
assembly), and `[LoggerMessage]` attributes refer to those constants as
`<FeatureBase> + N` rather than hard-coded numbers — the base lives in one
place and a feature-wide range shift is a one-line edit.

| Range       | Constant namespace                    | Feature area                                                   |
| ----------- | ------------------------------------- | -------------------------------------------------------------- |
| `1000–1099` | `Abblix.Jwt.LogEvents.Jwt.*`          | `Abblix.Jwt` (signing, validation, encryption, key management) |
| `2000–2099` | `Abblix.Oidc.Server.LogEvents.Endpoints.*`  | `Endpoints/Authorization`, `Endpoints/Token`, response builders |
| `3000–3099` | `Abblix.Oidc.Server.LogEvents.ClientAuth.*` | `Features/ClientAuthentication`                                |
| `4000–4099` | `Abblix.Oidc.Server.LogEvents.Dcr.*`        | `Endpoints/DynamicClientManagement`                            |
| `5000–5099` | `Abblix.Oidc.Server.LogEvents.Tokens.*`     | `Features/Tokens` (validation, issuance, revocation)           |
| `6000–6099` | `Abblix.Oidc.Server.LogEvents.HttpFetch.*`  | `Features/SecureHttpFetch`                                     |
| `7000–7099` | `Abblix.Oidc.Server.LogEvents.Device.*`     | `Features/DeviceAuthorization`, `Features/BackChannelAuthentication` |
| `8000–8099` | `Abblix.Oidc.Server.LogEvents.Licensing.*`  | `Features/Licensing`                                           |
| `9000–9099` | `Abblix.Oidc.Server.LogEvents.Misc.*`       | Misc — Discovery, Storage, Issuer, Session, RandomGenerator    |

Each per-feature nested class holds `private const int Base = <range start>` and exposes
named events as `public const int SomeEvent = Base + N`. Adding a new event = one line in
the nested class plus one `[LoggerMessage]`-tagged partial method in the consuming file.

When a feature area approaches its 100-event ceiling, expand to a 4-digit
suffix (e.g. `8100–8199`) rather than borrowing from a neighbour — borrowing
breaks range-based filtering.

## Authoring rules

- Class hosting the `[LoggerMessage]` methods is `partial` so the source
  generator can emit the implementation alongside the declaration.
- Logger is injected via the **primary constructor** as
  `ILogger<TThisClass> logger`; do not inject `ILoggerFactory` and create the
  logger lazily.
- `[LoggerMessage]` methods are `private partial void` (or `private partial
  Task` for the rare async logging case). Place them at the bottom of the
  class file, below the regular methods, in EventId order.
- The `Message` template uses **named placeholders** in `{PascalCase}` that
  match the parameter names exactly — `{ClientId}`, not `{client_id}` or
  `{0}`. Aggregators (Loki, Seq, Application Insights) index them as
  structured fields.
- Pick the lowest log level that captures the event without flooding logs:
  - `Trace` — high-volume internal state useful only in dev debug.
  - `Debug` — useful for flow-tracing in production diagnostics.
  - `Information` — successful business events the operator wants to see.
  - `Warning` — unexpected but recoverable (input rejected, retry triggered,
    rate-limit kicked in).
  - `Error` — operation failed in a way that needs operator attention.
  - `Critical` — service-level outage; reserved for impossible-to-recover
    conditions.

## Example

```csharp
// LogEvents.cs (one entry per event, grouped under the feature class)
internal static class LogEvents
{
    public static class Tokens
    {
        private const int Base = 5000;

        public const int ClientJwtValidationFailed = Base + 1;
    }
}

// ClientJwtValidator.cs
internal partial class ClientJwtValidator(
    IAuthServiceJwtValidator validator,
    ILogger<ClientJwtValidator> logger) : IClientJwtValidator
{
    public async Task<Result<...>> ValidateAsync(string jwt, ...)
    {
        var result = await validator.ValidateAsync(jwt);
        if (result.TryGetFailure(out var error))
        {
            LogJwtValidationFailed(error.ToString());
            return error;
        }
        // ...
    }

    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidationFailed,
        Level = LogLevel.Warning,
        Message = "Client JWT assertion validation failed: {Reason}")]
    private partial void LogJwtValidationFailed(string Reason);
}
```

Open the constant from the attribute to navigate to the canonical allocation;
add new events near existing ones in the same nested class.

## Migrations

When migrating an existing `ILogger.LogXxx(...)` call:

- **Preserve the message text verbatim** — log aggregators may have alerts or
  dashboards keyed on the literal text. Renaming a placeholder is allowed only
  when the underlying value is the same; reordering is allowed.
- **Choose EventId from the feature's range**. When the source file is the
  first in a range, start from the range's base (e.g. `1001`) and increment.
- **Make the class `partial`** — the source generator emits the body. If the
  class is `sealed`, that's fine; `sealed partial` works.
