# Abblix.SecurityEvents.CAEP

The OpenID Continuous Access Evaluation Profile 1.0 event dictionary for [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents): typed payload models and event type identifiers for the eight CAEP events, registered over the Security Events core in one call.

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
if (token.EventPayloads[CaepEventTypes.SessionRevoked] is SessionRevokedPayload revoked)
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

## License

Abblix.SecurityEvents.CAEP is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
