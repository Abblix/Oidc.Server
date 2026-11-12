// Abblix OIDC Client Library
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

using System.Net.Http.Headers;
using Abblix.Oidc.Client.Common.Constants;

namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// What a resource server said when it refused a bearer token.
/// </summary>
/// <remarks>
/// RFC 6750 section 3 puts the refusal in the <c>WWW-Authenticate</c> header rather than the body, so this
/// is where the reason lives: whether the token was rejected, whether it was merely insufficient for what
/// was asked, and which scopes would have been enough.
/// The distinction is the whole value. A 401 carrying <c>invalid_token</c> says sign in again; a 403
/// carrying <c>insufficient_scope</c> says ask for more scope, and signing in again with the same scopes
/// will fail identically forever.
/// </remarks>
/// <param name="Realm">The protection space, when the server named one.</param>
/// <param name="Error">The error code from <see cref="ResourceErrorCodes"/>, when the server sent one.</param>
/// <param name="ErrorDescription">The human-readable explanation, when the server sent one.</param>
/// <param name="ErrorUri">A page about the error, when the server sent one and it parses as a URI.</param>
/// <param name="Scope">
/// The scopes the server says are required, from an <c>insufficient_scope</c> challenge. Space-delimited on
/// the wire (RFC 6750 section 3), split here, case preserved - scope values are case-sensitive.
/// </param>
/// <param name="IsMalformed">
/// Whether the challenge broke a rule of its own grammar. Reported rather than repaired: a challenge that
/// repeats a parameter RFC 6750 section 3 says "MUST NOT appear more than once" is one whose sender is
/// confused or is not the server, and quietly taking the last value picks one of two answers on its behalf.
/// </param>
public sealed record BearerChallenge(
    string? Realm,
    string? Error,
    string? ErrorDescription,
    Uri? ErrorUri,
    IReadOnlyCollection<string> Scope,
    bool IsMalformed)
{
    /// <summary>
    /// Reads the Bearer challenge out of a response's headers, if it carries one.
    /// </summary>
    /// <param name="headers">The response headers.</param>
    /// <returns>The challenge, or <c>null</c> when no Bearer challenge was sent.</returns>
    /// <remarks>
    /// A response may carry several challenges for several schemes (RFC 9110 section 11.6.1); only the
    /// Bearer one is read, and the others are left alone rather than treated as malformed - a server
    /// offering an alternative this client cannot use has done nothing wrong.
    /// </remarks>
    public static BearerChallenge? Read(HttpHeaderValueCollection<AuthenticationHeaderValue> headers)
    {
        var bearer = headers.FirstOrDefault(
            header => string.Equals(header.Scheme, TokenTypes.Bearer, StringComparison.OrdinalIgnoreCase));

        return bearer is null ? null : Parse(bearer.Parameter);
    }

    /// <summary>
    /// Reads the auth-params of a Bearer challenge.
    /// </summary>
    /// <remarks>
    /// Unknown parameters are tolerated. RFC 6750 section 3 defines four and leaves the grammar open, so a
    /// server sending a fifth is extending rather than misbehaving, and refusing the whole challenge over it
    /// would throw away the parameters that were understood.
    /// </remarks>
    private static BearerChallenge Parse(string? parameters)
    {
        string? realm = null, error = null, errorDescription = null, errorUri = null, scope = null;
        var malformed = false;

        foreach (var (name, value) in Split(parameters))
        {
            // Each of the four "MUST NOT appear more than once" (RFC 6750 section 3). A repeat leaves the
            // value null and marks the challenge, so a caller reads "the server did not say" rather than
            // one of two things it did say.
            switch (name.ToLowerInvariant())
            {
                case "realm":
                    malformed |= !Take(ref realm, value);
                    break;

                case "error":
                    malformed |= !Take(ref error, value);
                    break;

                case "error_description":
                    malformed |= !Take(ref errorDescription, value);
                    break;

                case "error_uri":
                    malformed |= !Take(ref errorUri, value);
                    break;

                case "scope":
                    malformed |= !Take(ref scope, value);
                    break;

                default:
                    // An extension parameter. Not ours to judge.
                    break;
            }
        }

        return new BearerChallenge(
            realm,
            error,
            errorDescription,
            Uri.TryCreate(errorUri, UriKind.Absolute, out var parsedErrorUri) ? parsedErrorUri : null,
            scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [],
            malformed);
    }

    /// <summary>
    /// Records a value, or reports that this parameter had already been seen.
    /// </summary>
    private static bool Take(ref string? slot, string value)
    {
        if (slot is not null)
        {
            slot = null;
            return false;
        }

        slot = value;
        return true;
    }

    /// <summary>
    /// Splits the challenge into its name-value pairs.
    /// </summary>
    /// <remarks>
    /// RFC 6750 section 3 gives every parameter's value as a quoted-string, so the quotes are stripped and a
    /// backslash escape inside them is unescaped. A parameter with no <c>=</c> is skipped: the grammar has
    /// no bare tokens, so it is not a parameter this challenge defines.
    /// </remarks>
    private static IEnumerable<(string Name, string Value)> Split(string? parameters)
    {
        if (string.IsNullOrEmpty(parameters))
            yield break;

        foreach (var part in SplitOutsideQuotes(parameters))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0)
                continue;

            var name = part[..separator].Trim();
            var value = part[(separator + 1)..].Trim();

            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
                value = value[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\");

            yield return (name, value);
        }
    }

    /// <summary>
    /// Splits on commas that are not inside a quoted string.
    /// </summary>
    /// <remarks>
    /// A plain <c>Split(',')</c> would cut an <c>error_description</c> in half at the first comma in its
    /// prose, which is exactly where a server puts one.
    /// </remarks>
    private static IEnumerable<string> SplitOutsideQuotes(string parameters)
    {
        var quoted = false;
        var escaped = false;
        var start = 0;

        for (var index = 0; index < parameters.Length; index++)
        {
            var character = parameters[index];

            if (escaped)
                escaped = false;
            else if (character == '\\' && quoted)
                escaped = true;
            else if (character == '"')
                quoted = !quoted;
            else if (character == ',' && !quoted)
            {
                yield return parameters[start..index];
                start = index + 1;
            }
        }

        yield return parameters[start..];
    }
}
