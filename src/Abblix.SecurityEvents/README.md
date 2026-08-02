# Abblix.SecurityEvents

Security Event Tokens ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417.html)) and Subject
Identifiers ([RFC 9493](https://www.rfc-editor.org/rfc/rfc9493.html)) for .NET.

## Building a Security Event Token

A SET is a JWT whose claims describe a security event. The builder enforces what the
specification requires - issuer, token identifier, issue time and at least one event statement -
and refuses what the profile forbids: the `typ` header is fixed to `secevent+jwt`, and `exp`
cannot be written, because its absence is what stops a SET doubling as an ID or access token.

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

## Subject Identifiers

A Subject Identifier is a JSON object that says who or what an event is about, and says it in a
way that names the identification mechanism rather than leaving it to be guessed. An email
address, an issuer and subject pair, an opaque database key and a phone number can all identify
the same subject, and without the format name a receiver cannot tell which mechanism it is
holding. What the subject *is* - a user, a mailbox, a device - stays between the transmitter and
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

A name that RFC 9493 already defines cannot be rebound, so a custom format can never change how a
standard document is read.

## License

Abblix.SecurityEvents is licensed under the Abblix license agreement. See
[LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
