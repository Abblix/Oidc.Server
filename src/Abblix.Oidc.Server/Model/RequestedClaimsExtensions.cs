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
/// Reading what a <c>claims</c> request will accept: the end users for <c>sub</c>, and the authentication
/// levels for <c>acr</c>.
/// </summary>
public static class RequestedClaimsExtensions
{
    /// <summary>
    /// The end users this request will accept for <c>sub</c>: an empty array when it named none in
    /// particular, or a failure describing a qualifier that is malformed or that nobody can satisfy.
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
    /// acceptable, which is the guaranteed mismatch that same section prescribes an outcome for - said
    /// here as a refusal naming the contradiction, rather than as a set that silently matches no session
    /// and sends the end user to authenticate for a request that can never be answered.
    /// </para>
    /// <para>
    /// Only the <c>id_token</c> member is read, deliberately. Section 3.1.2.2 scopes the requirement to a
    /// <c>sub</c> "requested with a specific value for the ID Token", and a <c>userinfo.sub</c> entry asks
    /// what the UserInfo response should contain rather than who the request is about - Section 5.5.1's
    /// mismatch rule then governs that response, not the authentication.
    /// </para>
    /// </remarks>
    public static Result<string[], string> RequestedSubjects(this RequestedClaims? claims)
    {
        if (claims?.IdToken is not { } requested ||
            !requested.TryGetValue(IanaClaimTypes.Sub, out var details) ||
            details is null)
            return Array.Empty<string>();

        string? value = null;
        if (details.Value is not null && !TryReadQualifier(details.Value, out value))
            return MalformedSubject;

        string[]? values = null;
        if (details.Values is { } requestedValues)
        {
            values = new string[requestedValues.Length];
            for (var i = 0; i < requestedValues.Length; i++)
            {
                if (!TryReadQualifier(requestedValues[i], out var subject))
                    return MalformedSubject;

                values[i] = subject;
            }
        }

        return (value, values) switch
        {
            (null, null) => Array.Empty<string>(),
            (null, []) => NoAcceptableSubject,
            (null, { } many) => many,
            ({ } one, null) => new[] { one },
            ({ } one, { } many) => many.Contains(one, StringComparer.Ordinal)
                ? new[] { one }
                : NoAcceptableSubject,
        };
    }

    /// <summary>
    /// The authentication levels this request requires of the ID token: an empty array when it requires
    /// none, or a failure when its qualifiers name a level nobody can hold.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 5.5.1.1 conditions its rule on three things the request states: the
    /// <c>acr</c> claim is essential, it is asked of the ID token, and it carries "a value or values
    /// parameter requesting specific Authentication Context Class Reference values". Given those, the server
    /// "MUST return an acr Claim Value that matches one of the requested values", and "MUST treat that
    /// outcome as a failed authentication attempt" when it cannot. A fourth condition of that sentence, that
    /// the implementation supports the <c>claims</c> parameter, this server meets everywhere: its
    /// authorization metadata publishes <c>claims_parameter_supported</c> as true.
    /// <para>
    /// A voluntary <c>acr</c> is read as requiring nothing, which the same section says outright: the
    /// relying party "MAY request the acr Claim as a Voluntary Claim ... by not including
    /// <c>"essential": true</c>", and an unmet voluntary claim is not a failed authentication. So is an
    /// essential one naming no values: it accepts whatever the session holds.
    /// </para>
    /// <para>
    /// The two qualifiers bind together, as they do for <c>sub</c> above and for the same reason, and a
    /// request whose qualifiers accept no level at all - an empty choice, or a <c>value</c> outside its own
    /// <c>values</c> - is a failure rather than an empty set, because an empty set is how this answer says
    /// that nothing was required.
    /// </para>
    /// </remarks>
    public static Result<string[], string> RequiredAuthContextClassRefs(this RequestedClaims? claims)
    {
        if (claims?.IdToken is not { } requested ||
            !requested.TryGetValue(IanaClaimTypes.Acr, out var details) ||
            details is not { Essential: true })
            return Array.Empty<string>();

        string? value = null;
        if (details.Value is not null && !TryReadQualifier(details.Value, out value))
            return MalformedAcr;

        string[]? values = null;
        if (details.Values is { } requestedValues)
        {
            values = new string[requestedValues.Length];
            for (var i = 0; i < requestedValues.Length; i++)
            {
                if (!TryReadQualifier(requestedValues[i], out var level))
                    return MalformedAcr;

                values[i] = level;
            }
        }

        return (value, values) switch
        {
            (null, null) => Array.Empty<string>(),
            (null, []) => NoAcceptableAcr,
            (null, { } many) => many,
            ({ } one, null) => new[] { one },
            ({ } one, { } many) => many.Contains(one, StringComparer.Ordinal)
                ? new[] { one }
                : NoAcceptableAcr,
        };
    }

    private const string MalformedAcr = "The acr claim was requested with a value that is not a string";

    private const string NoAcceptableAcr =
        "The acr claim was requested with qualifiers no authentication can satisfy";

    private const string MalformedSubject = "The sub claim was requested with a value that is not a string";

    private const string NoAcceptableSubject =
        "The sub claim was requested with qualifiers no end user can satisfy";

    /// <summary>
    /// Reads one qualifier of a requested claim, failing when it is not a string.
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
    private static bool TryReadQualifier(object? requested, [NotNullWhen(true)] out string? subject)
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
