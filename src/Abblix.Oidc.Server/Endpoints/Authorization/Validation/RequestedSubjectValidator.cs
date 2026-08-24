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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Records the end users a <c>claims</c> request will accept for <c>sub</c>, so the endpoint can honour them
/// when it chooses a session.
/// </summary>
/// <remarks>
/// This is the second way of asking what <c>id_token_hint</c> asks, and OpenID Connect Core 1.0 Section
/// 3.1.2.2 states them as one requirement: "If the <c>sub</c> (subject) Claim is requested with a specific
/// value for the ID Token, the Authorization Server MUST only send a positive response if the End-User
/// identified by that <c>sub</c> value has an active session with the Authorization Server or has been
/// Authenticated as a result of the request. The Authorization Server MUST NOT reply with an ID Token or
/// Access Token for a different user, even if they have an active session with the Authorization Server. Such
/// a request can be made either using an <c>id_token_hint</c> parameter or by requesting a specific Claim
/// Value as described in Section 5.5.1, if the <c>claims</c> parameter is supported by the implementation."
/// Section 5.5.1 says the same from the other end: "If the Claim was <c>sub</c>, a mismatch MUST cause the
/// authentication to fail".
/// <para>
/// The condition attached to that MUST is met here rather than left open: the discovery document advertises
/// <c>claims_parameter_supported</c>, so a client is entitled to expect the parameter to decide something.
/// </para>
/// <para>
/// Runs beside <see cref="IdTokenHintValidator"/> and after the validators that resolve the redirect URI and
/// the response mode, for the same reason: its refusals are the kind RFC 6749 Section 4.1.2.1 says the client
/// must be told about by redirection, and before those there is nowhere to tell it.
/// </para>
/// </remarks>
public class RequestedSubjectValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        if (context.Request.Claims?.IdToken is not { } requested ||
            !requested.TryGetValue(IanaClaimTypes.Sub, out var details) ||
            details is null)
            return null;

        string? value = null;
        if (details.Value is not null && !TryReadSubject(details.Value, out value))
            return MalformedSubject(context);

        string[]? values = null;
        if (details.Values is { } requestedValues)
        {
            values = new string[requestedValues.Length];
            for (var i = 0; i < requestedValues.Length; i++)
            {
                if (!TryReadSubject(requestedValues[i], out var subject))
                    return MalformedSubject(context);

                values[i] = subject;
            }
        }

        if (value is null && values is null)
            return null;

        // Section 5.5.1 defines both qualifiers as OPTIONAL and says nothing about carrying them together, so
        // a request doing so is read as stating both constraints: the subject has to be the one named by
        // "value" AND one of those listed in "values". Incompatible constraints leave nothing acceptable,
        // which is the guaranteed mismatch that same section already prescribes an outcome for.
        context.RequestedSubjects = (value, values) switch
        {
            (null, { } many) => many,
            ({ } one, null) => [one],
            ({ } one, { } many) => many.Contains(one, StringComparer.Ordinal) ? [one] : [],

            // Unreachable past the guard above, and stated rather than discarded so that removing the guard
            // fails loudly here instead of silently recording "no constraint" for a request that stated one.
            _ => throw new InvalidOperationException(
                $"Neither {nameof(RequestedClaimDetails.Value)} nor {nameof(RequestedClaimDetails.Values)} " +
                $"was requested for the {IanaClaimTypes.Sub} claim"),
        };

        return null;
    }

    private static AuthorizationRequestValidationError MalformedSubject(AuthorizationValidationContext context)
        => context.InvalidRequest("The sub claim was requested with a value that is not a string");

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
    /// outright instead of answering <c>login_required</c> and leaving the client to guess.
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
