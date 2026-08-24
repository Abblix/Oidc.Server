// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Reading the end users a <c>claims</c> request will accept for <c>sub</c>.
/// </summary>
public static class RequestedClaimsExtensions
{
    /// <summary>
    /// The end users this request will accept for <c>sub</c>: <c>null</c> when it named none in particular,
    /// an empty array when it named a combination nobody can satisfy, or a failure describing a malformed
    /// qualifier.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.2 names this and <c>id_token_hint</c> as two ways to make one
    /// request, so every endpoint accepting either has to read both the same way. Section 5.5.1 gives the
    /// qualifiers their meaning: <c>value</c> "requests that the Claim be returned with a particular value",
    /// <c>values</c> is "processed equivalently to a value request, except that a choice of acceptable Claim
    /// values is provided", and "if the Claim was <c>sub</c>, a mismatch MUST cause the authentication to
    /// fail".
    /// <para>
    /// Section 5.5.1 defines both qualifiers as OPTIONAL and says nothing about carrying them together, so a
    /// request doing so is read as stating both constraints: the subject has to be the one named by
    /// <c>value</c> AND one of those listed in <c>values</c>. Incompatible constraints leave nothing
    /// acceptable, which is the guaranteed mismatch that same section already prescribes an outcome for.
    /// </para>
    /// </remarks>
    public static Result<string[]?, string> RequestedSubjects(this RequestedClaims? claims)
    {
        if (claims?.IdToken is not { } requested ||
            !requested.TryGetValue(IanaClaimTypes.Sub, out var details) ||
            details is null)
            return (string[]?)null;

        string? value = null;
        if (details.Value is not null && !TryReadSubject(details.Value, out value))
            return MalformedSubject;

        string[]? values = null;
        if (details.Values is { } requestedValues)
        {
            values = new string[requestedValues.Length];
            for (var i = 0; i < requestedValues.Length; i++)
            {
                if (!TryReadSubject(requestedValues[i], out var subject))
                    return MalformedSubject;

                values[i] = subject;
            }
        }

        return (value, values) switch
        {
            (null, null) => (string[]?)null,
            (null, { } many) => many,
            ({ } one, null) => [one],
            ({ } one, { } many) => many.Contains(one, StringComparer.Ordinal) ? [one] : [],
        };
    }

    private const string MalformedSubject = "The sub claim was requested with a value that is not a string";

    /// <summary>
    /// Reads a requested <c>sub</c> value, failing when the qualifier is not a string.
    /// </summary>
    /// <remarks>
    /// Two shapes arrive here because the same property carries both. A request read off the wire holds a
    /// <see cref="JsonElement"/>, since <see cref="RequestedClaimDetails.Value"/> is typed as
    /// <see cref="object"/> and that is what the JSON reader produces. A request retrieved by
    /// <c>request_uri</c> was round-tripped through the protobuf store, whose mapper turns a string value back
    /// into a <see cref="string"/>. Handling only the first would leave the requirement unenforced on exactly
    /// the pushed-request path, with nothing failing to say so.
    /// <para>
    /// Anything else is a malformed request rather than a subject nobody matches. Section 5.5.1 requires the
    /// qualifier to be "a valid value for the Claim being requested" and Section 2 makes <c>sub</c> a string,
    /// so a number or an object states a condition no end user could ever satisfy - which is worth saying
    /// outright instead of refusing as though nobody were logged in.
    /// </para>
    /// </remarks>
    private static bool TryReadSubject(object? requested, [NotNullWhen(true)] out string? subject)
    {
        switch (requested)
        {
            case string text:
                subject = text;
                return true;

            case JsonElement { ValueKind: JsonValueKind.String } element:
                subject = element.GetString();
                return subject is not null;

            default:
                subject = null;
                return false;
        }
    }
}
