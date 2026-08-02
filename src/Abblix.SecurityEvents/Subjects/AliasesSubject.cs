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

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by several Subject Identifiers at once, each naming the same entity
/// (RFC 9493 Section 3.2.8). It is meant for the case where a transmitter has shared a variety of
/// identifiers with a receiver and does not know which of them the receiver will recognise.
/// </summary>
/// <remarks>
/// Presenting several identifiers together tells the receiver that they belong to one subject,
/// which is information in its own right. RFC 9493 Section 6.1 asks a transmitter to send them
/// together only where the receiver already knows they are related, or where the correlation is
/// what the use case is about.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AliasesSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates an Aliases Subject Identifier.
    /// </summary>
    /// <param name="identifiers">
    /// The Subject Identifiers naming the subject. REQUIRED, must hold at least one entry, and
    /// must hold no Aliases Subject Identifier of its own.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="identifiers"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="identifiers"/> is empty, holds a null entry, or holds a nested
    /// <see cref="AliasesSubject"/>.</exception>
    [JsonConstructor]
    public AliasesSubject(IReadOnlyList<SubjectIdentifier> identifiers)
        : base(SubjectFormats.Aliases)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        if (identifiers.Count == 0)
        {
            throw new ArgumentException(
                $"The '{SubjectMemberNames.Identifiers}' member is REQUIRED and must not be null or empty "
                + "(RFC 9493 Section 3.2.8).",
                nameof(identifiers));
        }

        for (var i = 0; i < identifiers.Count; i++)
        {
            if (identifiers[i] is null)
            {
                throw new ArgumentException(
                    $"The '{SubjectMemberNames.Identifiers}' member holds a null at index {i}; every entry "
                    + "must be a Subject Identifier (RFC 9493 Section 3.2.8).",
                    nameof(identifiers));
            }

            // RFC 9493 Section 3.2.8: "'aliases' Subject Identifiers MUST NOT be nested". Rejecting it
            // on construction rather than on serialization is what makes the rule hold on the way IN as
            // well: a nested alias arriving over the wire dies in the same constructor the sender's own
            // code would have died in.
            if (identifiers[i] is AliasesSubject)
            {
                throw new ArgumentException(
                    $"The '{SubjectMemberNames.Identifiers}' member holds a nested "
                    + $"'{SubjectFormats.Aliases}' Subject Identifier at index {i}, which "
                    + "RFC 9493 Section 3.2.8 forbids.",
                    nameof(identifiers));
            }
        }

        // A copy, not the caller's list: the checks above are worth nothing if the caller can
        // Clear() the list or slip a nested alias in after construction. The read-only wrapper
        // matters too - a bare array could be cast back and its elements replaced - so what was
        // validated is what will be serialized.
        Identifiers = Array.AsReadOnly(identifiers.ToArray());
    }

    /// <summary>
    /// Creates an Aliases Subject Identifier from the identifiers given.
    /// </summary>
    /// <param name="identifiers">
    /// The Subject Identifiers naming the subject, under the same conditions as the primary
    /// constructor.</param>
    public AliasesSubject(params SubjectIdentifier[] identifiers)
        : this((IReadOnlyList<SubjectIdentifier>)identifiers)
    {
    }

    /// <summary>
    /// The Subject Identifiers naming the subject, each identifying the same entity.
    /// </summary>
    /// <remarks>
    /// The same Identifier Format may appear more than once, which is how a subject with two email
    /// addresses is expressed. RFC 9493 Section 3.2.8 says exact duplicates SHOULD NOT appear;
    /// that is a SHOULD NOT rather than a MUST NOT, so a duplicate is left to the caller and never
    /// silently dropped here.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Identifiers)]
    public IReadOnlyList<SubjectIdentifier> Identifiers { get; }
}
