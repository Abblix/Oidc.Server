// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using System.Text;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Builds <c>WWW-Authenticate</c> challenge values for the Bearer scheme (RFC 6750 §3)
/// and the DPoP scheme (RFC 9449 §7.1). Endpoint-agnostic and framework-agnostic so the
/// same emission logic serves UserInfo, introspection, revocation, and any future
/// protected endpoint, regardless of whether the host is ASP.NET Core MVC, minimal APIs,
/// or another framework altogether.
/// </summary>
/// <remarks>
/// The Bearer challenge attaches <c>error</c> / <c>error_description</c> when the inbound
/// failure is in fact a Bearer-token failure (<c>invalid_token</c>, <c>insufficient_scope</c>).
/// When the failure is a DPoP-specific error and Bearer is advertised alongside DPoP, the
/// Bearer line carries only the realm - RFC 9449 §7.1 example: «the Bearer scheme didn't
/// fail; the client used the DPoP scheme», so attaching <c>error="invalid_dpop_proof"</c>
/// to the Bearer line would be misleading.
/// </remarks>
public static class WwwAuthenticateBuilder
{
    /// <summary>
    /// Builds a <c>WWW-Authenticate: Bearer</c> challenge per RFC 6750 §3. The <c>error</c>
    /// and <c>error_description</c> attributes are emitted only when the inbound failure is
    /// a Bearer-scheme failure; pass <paramref name="includeError"/> as <c>false</c> for
    /// dual-scheme responses where the Bearer line is informational.
    /// </summary>
    public static string BuildBearerChallenge(OidcError error, string? realm, bool includeError = true)
    {
        var challenge = new Challenge(TokenTypes.Bearer);
        challenge.Append("realm", realm);

        // RFC 6750 §3.1: when the request carried no authentication information at all, the
        // challenge must stay bare - no error code or description, just the scheme (and realm).
        if (includeError && error is not MissingAuthenticationError)
        {
            challenge.Append("error", error.Error);
            challenge.Append("error_description", error.ErrorDescription);
        }

        return challenge.ToString();
    }

    /// <summary>
    /// Builds a <c>WWW-Authenticate: Basic</c> challenge per RFC 7617 §2 for client-authentication
    /// failures (RFC 6749 §5.2). Only the realm parameter is emitted: unlike Bearer (RFC 6750 §3),
    /// the Basic scheme defines no error attributes, so the error itself stays in the JSON body.
    /// </summary>
    public static string BuildBasicChallenge(string? realm)
    {
        var challenge = new Challenge(TokenTypes.Basic);
        challenge.Append("realm", realm);
        return challenge.ToString();
    }

    /// <summary>
    /// Builds a <c>WWW-Authenticate: DPoP</c> challenge per RFC 9449 §7.1, advertising the
    /// JWS algorithms the AS accepts on a proof.
    /// </summary>
    public static string BuildDPoPChallenge(OidcError error, string? realm, IEnumerable<string> algs)
    {
        var challenge = new Challenge(TokenTypes.DPoP);
        challenge.Append("realm", realm);

        // RFC 6750 §3.1 applies to the DPoP line too: an unauthenticated request gets a bare
        // challenge advertising the scheme, without error attributes.
        if (error is not MissingAuthenticationError)
        {
            challenge.Append("error", error.Error);
            challenge.Append("error_description", error.ErrorDescription);
        }

        challenge.Append("algs", string.Join(' ', algs));
        return challenge.ToString();
    }

    /// <summary>
    /// Builds the full set of <c>WWW-Authenticate</c> challenge lines for an error
    /// response. Returns DPoP first, Bearer second (matching the RFC 9449 §7.1 example
    /// ordering) when both schemes are advertised.
    /// </summary>
    public static IReadOnlyList<string> BuildChallenges(
        OidcError error,
        string? realm,
        IEnumerable<string> dpopAlgs,
        bool advertiseBearer)
    {
        var dpop = BuildDPoPChallenge(error, realm, dpopAlgs);
        if (!advertiseBearer)
            return [dpop];

        var bearer = BuildBearerChallenge(error, realm, includeError: false);
        return [dpop, bearer];
    }

    /// <summary>
    /// Accumulates a single <c>WWW-Authenticate</c> challenge value as
    /// <c>scheme name1="v1", name2="v2", ...</c>. Owns the comma-vs-space delimiter logic so
    /// callers stay declarative - they just append name/value pairs and skip empties.
    /// </summary>
    private sealed class Challenge(string scheme)
    {
        private readonly StringBuilder _builder = new(scheme);
        private bool _first = true;

        public void Append(string name, string? value)
        {
            if (string.IsNullOrEmpty(value))
                return;

            _builder
                .Append(_first ? " " : ", ")
                .Append(name)
                .Append("=\"");

            // RFC 7235 §2.2 / RFC 9110 §5.6.4: inside a quoted-string each `"` MUST be
            // backslash-escaped, and `\` itself MUST be doubled. Anything else (CR/LF
            // and other control bytes) is rejected upstream - mutating values silently
            // would obscure malformed inputs.
            foreach (var c in value)
            {
                if (c is '"' or '\\')
                    _builder.Append('\\');
                _builder.Append(c);
            }

            _builder.Append('"');
            _first = false;
        }

        public override string ToString() => _builder.ToString();
    }
}
