# Abblix.SecurityEvents

Security Event Tokens ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417.html)) and Subject
Identifiers ([RFC 9493](https://www.rfc-editor.org/rfc/rfc9493.html)) for .NET.

## Install

```bash
dotnet add package Abblix.SecurityEvents
```

## Building a Security Event Token

A SET is a JWT whose claims describe a security event. The builder enforces what the
specification requires - issuer, token identifier, issue time and at least one event statement -
and refuses what the profile forbids: the `typ` header is fixed to `secevent+jwt`, and `exp`
cannot be written.

RFC 8417 Section 2.2 rates `exp` NOT RECOMMENDED for a token that records
history, and Sections 4.1 and 4.2 make omitting it one of the layers that keep a SET from being
passed off as an ID or access token - defence in depth alongside explicit typing and a distinct
audience, all of which this package applies.

```csharp
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Subjects;

var compact = await new SecurityEventTokenBuilder()
    .WithIssuer("https://tenant.example.com")
    .WithAudience("https://receiver.example.com/events")
    .WithJwtId(Guid.NewGuid().ToString("N"))
    .WithEvent(
        "https://tenant.example.com/events/membership-changed",
        new JsonObject
        {
            ["subject"] = JsonSerializer.SerializeToNode<SubjectIdentifier>(
                new IssSubSubject("https://account.example.com", "a3f1c9e2")),
            ["change"] = "revoked",
        })
    .SignAsync(signer);
```

The signer is the seam to your cryptography: `ISecurityEventTokenSigner` owns key and algorithm
choice, and unless a token's integrity is ensured by other means, RFC 8417 requires it to be
signed. `Build()` alone returns the typed, unsigned model for inspection.

## Validating a Security Event Token

Validation is a composed profile behind one interface. The default profile runs the receiver
checks in their required order - parse, the `secevent+jwt` type header, the absence of `exp`,
the presence of events, the presence of the REQUIRED `jti`, the issuer allowlist, the
signature, the audience, the issued-at freshness window, and payload deserialization into the
registered models.

```csharp
var result = await validator.ValidateAsync(
    compact,
    new SecurityEventTokenValidationOptions
    {
        ExpectedAudience = "https://receiver.example.com/events",
        ExpectedIssuers = ["https://tenant.example.com"],
    });

if (result.TryGetSuccess(out var validated))
{
    // validated.Token is the typed SET; validated.EventPayloads holds the deserialized
    // payload per event identifier.
}
```

A consumer profile edits the default steps in place through the composition cursor
(`services.Decompose<ISecurityEventTokenValidator>()`) - inserting, replacing or removing steps
without this package changing.

A profile that removes or replaces a security-critical default
must say why through `SecurityEventsOptions.AllowInsecureValidation(reason)`: the guard demands
the acknowledgement when the validator is first constructed, logs it as a warning, and otherwise
refuses to construct. Every door that edits the composition is inside its reach; the one thing it
cannot cover is a host registering its own `ISecurityEventTokenValidator` after this call, which
replaces the profile and the guard together - the host visibly taking ownership of validation.

## Wiring into a host

```csharp
services.AddSecurityEvents(options =>
{
    options.Events.Register<MembershipChangedPayload>(
        "https://tenant.example.com/events/membership-changed");
    options.SigningKeySource = _ => Task.FromResult(signingKey); // transmitters only
});
services.AddJwksKeyResolution();      // receivers: issuers' keys from their published JWK Sets
services.AddDistributedMemoryCache(); // or Redis: the replay cache rides the host's IDistributedCache
services.AddDistributedReplayCache(); // receivers: "jti" replay protection over that store
```

A pure receiver registers a key resolver and never configures signing; a pure transmitter does
the reverse. Event registrations go through `options.Events`: registered event types deserialize
into their payload models, unregistered ones pass through as `UnknownEventPayload` rather than
failing. Every registration lets a host pre-registration win - with one loud exception: the
event registry has exactly one door (`options.Events`), and a second registry instance is
refused at wiring time rather than silently orphaning half the registrations.

## Delivery types

The data shapes of both standard delivery methods, without their transports: the media type and
error codes of push delivery ([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935.html)), and the
request and response models of poll delivery
([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936.html)). The HTTP side belongs to the consumer,
or to a Shared Signals package above this one.

## Subject Identifiers

A Subject Identifier is a JSON object that says who or what an event is about, and says it in a
way that names the identification mechanism rather than leaving it to be guessed. An email
address, an issuer and subject pair, an opaque database key and a phone number can all identify
the same subject, and without the format name a receiver cannot tell which mechanism it is
holding.

What the subject *is* - a user, a mailbox, a device - stays between the transmitter and
the receiver: the format never asserts it.

## What is here today

Every Identifier Format in the IANA registry, as a type of its own:

| Format | Type | Members |
|---|---|---|
| `account` | `AccountSubject` | `uri` |
| `email` | `EmailSubject` | `email` |
| `iss_sub` | `IssSubSubject` | `iss`, `sub` |
| `opaque` | `OpaqueSubject` | `id` |
| `phone_number` | `PhoneNumberSubject` | `phone_number` |
| `did` | `DidSubject` | `url` |
| `uri` | `UriSubject` | `uri` |
| `aliases` | `AliasesSubject` | `identifiers` |

And the formats OpenID Shared Signals Framework 1.0 defines on top of that registry - the same
vocabulary, with each constant's documentation naming which specification defines it:

| Format | Type | Members |
|---|---|---|
| `complex` | `ComplexSubject` | `user`, `device`, `session`, `application`, `tenant`, `org_unit`, `group`, extensions |
| `jwt_id` | `JwtIdSubject` | `iss`, `jti` |
| `saml_assertion_id` | `SamlAssertionIdSubject` | `issuer`, `assertion_id` |
| `ip-addresses` | `IpAddressesSubject` | `ip-addresses` |

## Reading and writing

Serialization is polymorphic on the `format` member, and it needs no configuration: the converter
is attached to the base type.

```csharp
using System.Text.Json;
using Abblix.SecurityEvents.Subjects;

SubjectIdentifier subject = new IssSubSubject("https://issuer.example.com/", "145234573");

var json = JsonSerializer.Serialize(subject);
// {"format":"iss_sub","iss":"https://issuer.example.com/","sub":"145234573"}

var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(json);
// an IssSubSubject
```

Reading is strict, because RFC 9493 is: a document missing a required member, carrying an empty
one, or carrying a member its format does not describe is rejected with a `JsonException` rather
than accepted and silently rewritten on the next serialization.

An `aliases` identifier holds several identifiers for one entity, and nesting one inside another is
rejected on construction, whether the value was built in code or read off the wire:

```csharp
var subject = new AliasesSubject(
    new EmailSubject("user@example.com"),
    new PhoneNumberSubject("+12065550100"));
```

## Comparing values

Nothing is canonicalised on the way in. RFC 9493 records that email canonicalisation is not
standardised and that a receiver cannot know the sending provider's algorithm, so folding a value
on arrival would answer that question on the application's behalf and destroy the original.

Two transformations are offered for use at comparison time. `EmailCanonicalization.ToComparableForm`
lowercases the domain, which is case-insensitive for every provider, and leaves the local part
alone. `PhoneNumberCanonicalization.ToComparableForm` removes presentation characters, which E.164
does not include in a number. Neither can merge two values that are genuinely distinct.

## Formats beyond the registry

A format defined by a later specification is a subclass plus one registration:

```csharp
var options = new JsonSerializerOptions
{
    Converters =
    {
        new SubjectIdentifierJsonConverter(
            new Dictionary<string, Type> { ["urn:example:format"] = typeof(MyFormatSubject) }),
    },
};
```

A name from the built-in vocabulary - RFC 9493 or Shared Signals - cannot be rebound, so a custom
format can never change how a standard document is read.

## Part of the Abblix family

The event dictionaries [Abblix.SecurityEvents.CAEP](https://www.nuget.org/packages/Abblix.SecurityEvents.CAEP) and [Abblix.SecurityEvents.RISC](https://www.nuget.org/packages/Abblix.SecurityEvents.RISC) register their typed payloads over this package's event registry, and [Abblix.SharedSignals](https://www.nuget.org/packages/Abblix.SharedSignals) carries the tokens built here over managed event streams; the full family lives in the [repository](https://github.com/Abblix/Oidc.Server).

## License

Abblix.SecurityEvents is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
