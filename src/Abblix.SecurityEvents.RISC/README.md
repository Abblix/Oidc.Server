# Abblix.SecurityEvents.RISC

The OpenID RISC Profile 1.0 (Risk Incident Sharing and Coordination) event dictionary for [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents): typed payload models and event type identifiers for the RISC events, registered over the Security Events core in one call. RISC is how providers protect a shared user together - a credential found in a breach or an account hijacked at one provider becomes a signal every other provider holding the same identifier can act on.

[Shared Signals in .NET: SSF, CAEP, RISC and Back-Channel Logout](https://www.abblix.com/en/docs/shared-signals-framework) places this vocabulary in the stack, and explains why account-level incidents travel the same envelope and the same streams as session events.

## Install

```bash
dotnet add package Abblix.SecurityEvents.RISC
```

## Events

| Event | Payload |
|---|---|
| `account-credential-change-required` | `AccountCredentialChangeRequiredPayload` |
| `account-purged` | `AccountPurgedPayload` |
| `account-disabled` | `AccountDisabledPayload` |
| `account-enabled` | `AccountEnabledPayload` |
| `identifier-changed` | `IdentifierChangedPayload` |
| `identifier-recycled` | `IdentifierRecycledPayload` |
| `credential-compromise` | `CredentialCompromisePayload` |
| `opt-in` | `OptInPayload` |
| `opt-out-initiated` | `OptOutInitiatedPayload` |
| `opt-out-cancelled` | `OptOutCancelledPayload` |
| `opt-out-effective` | `OptOutEffectivePayload` |
| `recovery-activated` | `RecoveryActivatedPayload` |
| `recovery-information-changed` | `RecoveryInformationChangedPayload` |
| `sessions-revoked` | `SessionsRevokedPayload` (deprecated by the specification; kept so it can still be received from older transmitters) |

The compromised credential's `credential_type` takes its values from the CAEP Credential Change event, per the RISC specification's own cross-reference - the constants live in [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP), which this package depends on.

## Receiving

```csharp
services.AddSecurityEvents(options => options.Events.RegisterRiscEvents());
```

One call teaches the registry the whole dictionary; a validated SET's payloads then arrive as the typed models, and the sink pattern-matches:

```csharp
if (token.EventPayloads?.GetValueOrDefault(RiscEventTypes.CredentialCompromise) is CredentialCompromisePayload compromise)
{
    // force a credential reset; compromise.CredentialType names what was burnt
}
```

Both dictionaries compose on one registry:

```csharp
services.AddSecurityEvents(options => options.Events.RegisterCaepEvents().RegisterRiscEvents());
```

## Transmitting

```csharp
await dispatcher.DispatchAsync(new SecurityEventDescriptor
{
    EventType = RiscEventTypes.CredentialCompromise,
    Subject = new IssSubSubject(issuer, subject),
    Payload = new CredentialCompromisePayload
    {
        CredentialType = CredentialChangePayload.CredentialTypes.Password,
    },
});
```

## Part of the Abblix product family

The events themselves travel over the [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals) transmitter and receiver; the sibling dictionary for session and access lifecycle is [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP), and both compose on one registry.

## License

Abblix.SecurityEvents.RISC is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
