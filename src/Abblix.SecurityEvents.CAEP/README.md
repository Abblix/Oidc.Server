# Abblix.SecurityEvents.CAEP

The OpenID Continuous Access Evaluation Profile (CAEP) 1.0 event dictionary for [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents): typed payload models and event type identifiers for the eight CAEP events, registered over the Security Events core in one call. CAEP is how cooperating services keep reacting to each other AFTER login - one provider revokes a session or sees a risk level shift, and every subscribed service learns of it without waiting for the next authentication.

## Install

```bash
dotnet add package Abblix.SecurityEvents.CAEP
```

## Events

| Event | Payload |
|---|---|
| `session-revoked` | `SessionRevokedPayload` |
| `token-claims-change` | `TokenClaimsChangePayload` |
| `credential-change` | `CredentialChangePayload` |
| `assurance-level-change` | `AssuranceLevelChangePayload` |
| `device-compliance-change` | `DeviceComplianceChangePayload` |
| `session-established` | `SessionEstablishedPayload` |
| `session-presented` | `SessionPresentedPayload` |
| `risk-level-change` | `RiskLevelChangePayload` |

Every payload carries the common CAEP claims - the event timestamp, the initiating entity, and the localizable administrative and end-user reasons - on the shared `CaepEventPayload` base.

## Receiving

```csharp
services.AddSecurityEvents(options => options.Events.RegisterCaepEvents());
```

One call teaches the registry the whole dictionary; a validated SET's payloads then arrive as the typed models, and the sink pattern-matches:

```csharp
if (token.EventPayloads?.GetValueOrDefault(CaepEventTypes.SessionRevoked) is SessionRevokedPayload revoked)
{
    // terminate the local session; revoked.ReasonUser carries the sentence to show
}
```

## Transmitting

```csharp
await dispatcher.DispatchAsync(new SecurityEventDescriptor
{
    EventType = CaepEventTypes.SessionRevoked,
    Subject = new ComplexSubject { Session = new OpaqueSubject(sessionId), User = userSubject },
    Payload = new SessionRevokedPayload
    {
        InitiatingEntity = CaepEventPayload.InitiatingEntities.Policy,
        ReasonAdmin = new Dictionary<string, string> { ["en"] = "Landspeed Policy Violation" },
        EventTimestamp = revokedAt,
    },
});
```

## Part of the Abblix family

The events themselves travel over the [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals) transmitter and receiver; the sibling dictionary for account risk incidents is [Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC), and both compose on one registry.

## License

Abblix.SecurityEvents.CAEP is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
