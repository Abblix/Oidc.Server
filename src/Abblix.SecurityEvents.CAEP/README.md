# Abblix.SecurityEvents.CAEP

The OpenID Continuous Access Evaluation Profile (CAEP) 1.0 event dictionary for [Abblix.SecurityEvents](https://www.nuget.org/packages/Abblix.SecurityEvents): typed payload models and event type identifiers for the eight CAEP events, registered over the Security Events core in one call. CAEP is how cooperating services keep reacting to each other AFTER login - one provider revokes a session or sees a risk level shift, and every subscribed service learns of it without waiting for the next authentication.

[Shared Signals in .NET: SSF, CAEP, RISC and Back-Channel Logout](https://www.abblix.com/en/docs/shared-signals-framework) places this vocabulary in the stack: the envelope underneath it, the streams that carry it, and what a receiver does with a session event once it arrives.

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

## Claiming the interoperability profile

`reason_admin` is optional in CAEP 1.0 and required of a transmitter by the CAEP Interoperability Profile
1.0: each of the three use cases in its Section 3 demands a non-empty object. The type cannot carry that
rule, because the base specification permits the member's absence - Section 2 makes the common claims
optional, Section 3.1.1 defines none of its own for `session-revoked` - so an empty payload is well-formed
and a receiver has to be able to hold one.

So the rule is a policy a deployment registers, and registering it is how the deployment claims the
profile:

```csharp
services.AddSingleton<IEventPayloadPolicy, CaepInteropProfilePolicy>();
```

The dispatcher then refuses the three events unless the member is populated, before anything is minted,
and says which event and what is missing. A host that registers nothing emits CAEP 1.0 events, which is a
smaller claim and a valid one.

The profile lets you claim fewer than three: "Support for all use cases listed herein is not required in
order to be considered compliant with this profile. An implementation can choose specific use cases to
support." Name the ones you claim and the others go out as plain CAEP 1.0 events:

```csharp
services.AddSingleton<IEventPayloadPolicy>(
    new CaepInteropProfilePolicy(CaepEventTypes.CredentialChange));
```

One rule the policy applies is the base specification's rather than the profile's: `reason_admin`, once
present, "MUST contain one or more key/value pairs" (CAEP 1.0 Section 2). An empty object is wrong with or
without the profile.

## Part of the Abblix product family

The events themselves travel over the [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals) transmitter and receiver; the sibling dictionary for account risk incidents is [Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC), and both compose on one registry.

## License

Abblix.SecurityEvents.CAEP is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
