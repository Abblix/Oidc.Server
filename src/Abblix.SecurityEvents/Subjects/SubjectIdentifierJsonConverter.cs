// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Reads and writes a <see cref="SubjectIdentifier"/> polymorphically, choosing the concrete
/// subtype by the "format" member that RFC 9493 Section 3 requires every Subject Identifier to
/// carry.
/// </summary>
/// <remarks>
/// <para>
/// The converter is attached to <see cref="SubjectIdentifier"/> itself, so it is reached whenever
/// the declared type is the abstract base - the nested identifiers of an
/// <see cref="AliasesSubject"/> among them - and is not reached when the declared type is already
/// a concrete subtype. That asymmetry is what lets <see cref="Write"/> hand the value straight back
/// to the serializer under its runtime type without re-entering this converter.
/// </para>
/// <para>
/// A format outside the built-in vocabulary is supported by deriving from
/// <see cref="SubjectIdentifier"/> and naming the subtype in the custom-formats map of
/// <see cref="SubjectIdentifierJsonConverter(IReadOnlyDictionary{string, Type})"/>, then placing
/// the resulting converter in the serializer options. Registration happens once, when the
/// converter is built, so the map cannot change under a reader mid-flight.
/// </para>
/// </remarks>
public sealed class SubjectIdentifierJsonConverter : JsonConverter<SubjectIdentifier>
{
    /// <summary>
    /// The built-in vocabulary: the IANA-registered RFC 9493 formats first, then the SSF 1.0
    /// extensions - one dispatch, with each name's provenance recorded on its
    /// <see cref="SubjectFormats"/> constant.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, Type> BuiltInFormats =
        new Dictionary<string, Type>(StringComparer.Ordinal)
        {
            [SubjectFormats.Account] = typeof(AccountSubject),
            [SubjectFormats.Email] = typeof(EmailSubject),
            [SubjectFormats.IssSub] = typeof(IssSubSubject),
            [SubjectFormats.Opaque] = typeof(OpaqueSubject),
            [SubjectFormats.PhoneNumber] = typeof(PhoneNumberSubject),
            [SubjectFormats.Did] = typeof(DidSubject),
            [SubjectFormats.Uri] = typeof(UriSubject),
            [SubjectFormats.Aliases] = typeof(AliasesSubject),
            [SubjectFormats.Complex] = typeof(ComplexSubject),
            [SubjectFormats.JwtId] = typeof(JwtIdSubject),
            [SubjectFormats.SamlAssertionId] = typeof(SamlAssertionIdSubject),
            [SubjectFormats.IpAddresses] = typeof(IpAddressesSubject),
        };

    private readonly IReadOnlyDictionary<string, Type> _formats;

    /// <summary>
    /// Creates a converter that understands the built-in vocabulary: the formats of the IANA
    /// registry (RFC 9493 Section 8.1.2) and the SSF 1.0 extensions (Sections 3.3, 3.5).
    /// </summary>
    public SubjectIdentifierJsonConverter()
        : this(null)
    {
    }

    /// <summary>
    /// Creates a converter that understands the built-in vocabulary plus the formats given.
    /// </summary>
    /// <param name="customFormats">
    /// Format names mapped to the concrete <see cref="SubjectIdentifier"/> subtype that models
    /// them. A name from the built-in vocabulary cannot be redefined here: those formats are the
    /// shared vocabulary of their specifications, and quietly rebinding one would make two
    /// parties disagree about a document both consider valid.</param>
    /// <exception cref="ArgumentException">
    /// A name is null or empty, collides with the built-in vocabulary, or is mapped to a type
    /// that is not a concrete subclass of <see cref="SubjectIdentifier"/>.</exception>
    public SubjectIdentifierJsonConverter(IReadOnlyDictionary<string, Type>? customFormats)
    {
        // Ordinal comparison: a format name is matched as an exact string on both kinds of key this
        // map holds. Registered names are lowercase ASCII by the IANA registration template (RFC 9493
        // Section 8.1.1, which binds only registrations); custom names are Collision-Resistant Names
        // (RFC 9493 Section 3), where case may be significant, so folding could merge two distinct
        // formats.
        var formats = new Dictionary<string, Type>(BuiltInFormats, StringComparer.Ordinal);

        if (customFormats != null)
        {
            foreach (var (format, type) in customFormats)
            {
                if (string.IsNullOrEmpty(format))
                {
                    throw new ArgumentException(
                        "A custom Identifier Format name must be neither null nor empty.",
                        nameof(customFormats));
                }

                if (BuiltInFormats.ContainsKey(format))
                {
                    throw new ArgumentException(
                        $"The Identifier Format '{format}' is part of the built-in vocabulary "
                        + "(RFC 9493 or SSF 1.0) and cannot be redefined.",
                        nameof(customFormats));
                }

                if (!typeof(SubjectIdentifier).IsAssignableFrom(type) || type.IsAbstract)
                {
                    throw new ArgumentException(
                        $"The Identifier Format '{format}' is mapped to '{type}', which is not a concrete "
                        + $"subclass of {nameof(SubjectIdentifier)}.",
                        nameof(customFormats));
                }

                formats.Add(format, type);
            }
        }

        _formats = formats;
    }

    /// <summary>
    /// Claims exactly the abstract base type and never a concrete subtype.
    /// </summary>
    /// <remarks>
    /// Both <see cref="Read"/> and <see cref="Write"/> re-enter the serializer under the concrete
    /// subtype, and they terminate only because that request is NOT routed back here. The base
    /// implementation currently answers with exact type equality, which provides that guarantee,
    /// but the guarantee is this converter's termination condition, so it is stated here rather
    /// than inherited from behaviour that lives only in convention.
    /// </remarks>
    public override bool CanConvert(Type typeToConvert) => typeToConvert == typeof(SubjectIdentifier);

    /// <summary>
    /// Reads a Subject Identifier, dispatching on its "format" member to the subtype that models
    /// that Identifier Format.
    /// </summary>
    /// <exception cref="JsonException">
    /// The value is not a JSON object, carries no usable "format" member, names a format this
    /// converter has not been told about, or holds members its Identifier Format does not permit.
    /// The subtype constructors enforce the member rules and throw <see cref="ArgumentException"/>;
    /// this boundary translates that into the exception type callers of a deserializer guard
    /// against, so untrusted input fails with one exception type however it is malformed.
    /// </exception>
    public override SubjectIdentifier? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException(
                $"A Subject Identifier is a JSON object (RFC 9493 Section 3), but the value read is "
                + $"{reader.TokenType}.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        if (!root.TryGetProperty(SubjectMemberNames.Format, out var formatElement)
            || formatElement.ValueKind != JsonValueKind.String)
        {
            throw new JsonException(
                $"A Subject Identifier must carry a '{SubjectMemberNames.Format}' member naming its "
                + "Identifier Format (RFC 9493 Section 3).");
        }

        var format = formatElement.GetString();
        if (string.IsNullOrEmpty(format))
        {
            throw new JsonException(
                $"The '{SubjectMemberNames.Format}' member is empty and so names no Identifier Format.");
        }

        if (!_formats.TryGetValue(format, out var type))
        {
            throw new JsonException($"Unknown Identifier Format: '{format}'.");
        }

        SubjectIdentifier? result;
        try
        {
            result = (SubjectIdentifier?)root.Deserialize(type, options);
        }
        catch (ArgumentException exception)
        {
            // The constructors are the single enforcement site for the member rules; here their
            // verdict is only re-labelled for the wire, where "this document is invalid" is a
            // JsonException by the serializer's own convention.
            throw new JsonException(exception.Message, exception);
        }

        // The document's format chose the type, but the type states its own format, and nothing
        // above guarantees a custom registration wired them consistently. Without this check a
        // mapping like "foo" => EmailSubject would read a "foo" document and silently write it
        // back as "email" - the two-parties-disagree outcome the registration rules exist to
        // prevent.
        if (result is not null && !string.Equals(result.Format, format, StringComparison.Ordinal))
        {
            throw new JsonException(
                $"The Identifier Format '{format}' is mapped to '{type}', which declares itself as "
                + $"'{result.Format}': the registration and the type disagree about the format's name.");
        }

        return result;
    }

    /// <summary>
    /// Writes a Subject Identifier in the shape its own Identifier Format defines, "format" member
    /// included.
    /// </summary>
    public override void Write(Utf8JsonWriter writer, SubjectIdentifier value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}
