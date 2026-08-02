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

using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// A Subject Identifier: a JSON object whose contents identify a subject within some context
/// (RFC 9493 Section 3).
/// </summary>
/// <remarks>
/// <para>
/// RFC 9493 Section 3 requires that a Subject Identifier "MUST NOT contain any members prohibited
/// or not described by its Identifier Format and MUST contain all members required by its
/// Identifier Format". That rule is kept structurally rather than by a validation pass, in two
/// halves. Each shipped subtype declares exactly the members its format describes and disallows
/// unmapped members on deserialization, so a document carrying a member its format does not
/// describe is rejected rather than accepted and then silently dropped by the next write. And
/// each subtype's constructor rejects a required member that is absent or empty, so the rule
/// binds a value built in code exactly as it binds one read off the wire.
/// </para>
/// <para>
/// The type says how a subject is identified, never what the subject is (RFC 9493 Section 3.1):
/// an <see cref="EmailSubject"/> may denote the person controlling the mailbox, the mailbox
/// itself, or anything else the transmitter and receiver both understand.
/// </para>
/// </remarks>
/// <param name="format">
/// The Identifier Format's name. A subtype passes its format as a constant, which is what makes
/// the format a property of the TYPE: it is set exactly once, here, so no subtype can carry an
/// attribute-decorated override of its own. An overridable property was tried first and is a
/// trap - the serializer does not inherit attributes across an override, so the base declaration
/// and the override serialize as two different members, "format" and "Format", in one document.
/// </param>
[JsonConverter(typeof(SubjectIdentifierJsonConverter))]
public abstract class SubjectIdentifier(string format)
{
    /// <summary>
    /// Places the "format" member ahead of the format-specific members. RFC 9493 does not order
    /// JSON members and neither does JSON itself, so this is legibility rather than conformance:
    /// it lets the specification's own examples be compared against our output as text.
    /// </summary>
    private const int FormatOrder = -1;

    /// <summary>
    /// The name of the Identifier Format this Subject Identifier conforms to (RFC 9493 Section 3).
    /// Values for the formats this library ships are listed in <see cref="SubjectFormats"/>.
    /// </summary>
    /// <remarks>
    /// The format member has its own normative sentence, distinct from the per-format member
    /// rules <see cref="RequirePresent"/> speaks for: "A Subject Identifier ... MUST contain a
    /// 'format' member whose value is the name of that Identifier Format" (RFC 9493 Section 3).
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Format)]
    [JsonPropertyOrder(FormatOrder)]
    public string Format { get; } = !string.IsNullOrEmpty(format)
        ? format
        : throw new ArgumentException(
            $"A Subject Identifier must carry a '{SubjectMemberNames.Format}' member naming its "
            + "Identifier Format (RFC 9493 Section 3).",
            nameof(format));

    /// <summary>
    /// Returns <paramref name="value"/> when the "REQUIRED and MUST NOT be null or empty"
    /// condition holds for it, and throws otherwise.
    /// </summary>
    /// <remarks>
    /// The message deliberately cites no section: for the formats this library ships the sentence
    /// comes from the format's own subsection of RFC 9493 Section 3.2, already cited on the
    /// property the value lands in, while a custom format calling this from another assembly owes
    /// the same sentence to its own specification, which this method cannot name.
    /// </remarks>
    /// <param name="value">The member value supplied by the caller.</param>
    /// <param name="memberName">
    /// The member's name on the wire, taken from <see cref="SubjectMemberNames"/>, so the message
    /// names what the reader of the JSON will look for rather than our parameter.</param>
    /// <param name="parameterName">
    /// Filled in by the compiler with the caller's argument expression; never passed explicitly.
    /// </param>
    protected static string RequirePresent(
        string? value,
        string memberName,
        [CallerArgumentExpression(nameof(value))] string? parameterName = null)
        => !string.IsNullOrEmpty(value)
            ? value
            : throw new ArgumentException(
                $"The '{memberName}' member is required and must not be null or empty.",
                parameterName);
}
