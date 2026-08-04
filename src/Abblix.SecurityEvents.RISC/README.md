# Abblix.SecurityEvents.RISC

The OpenID RISC Profile 1.0 (Risk Incident Sharing and Coordination) event dictionary for [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents): typed payload models and event type identifiers for the fourteen RISC events, registered over the Security Events core in one call.

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
| `sessions-revoked` | `SessionsRevokedPayload` (deprecated by the specification; kept for receiving from older transmitters) |

The compromised credential's `credential_type` takes its values from the CAEP Credential Change event, per the RISC specification's own cross-reference - the constants live in [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP), which this package depends on.

## Receiving

```csharp
services.AddSecurityEvents(options => options.Events.RegisterRiscEvents());
```

One call teaches the registry the whole dictionary; a validated SET's payloads then arrive as the typed models, and the sink pattern-matches:

```csharp
if (token.EventPayloads[RiscEventTypes.CredentialCompromise] is CredentialCompromisePayload compromise)
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

## License

Abblix.SecurityEvents.RISC is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
