// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
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
        // RFC 6750 §3.1: when the request carried no authentication information at all, the
        // challenge must stay bare - no error code or description, just the scheme (and realm).
        => includeError && error is not MissingAuthenticationError
            ? WwwAuthenticate.Challenge(TokenTypes.Bearer, realm, error.Error, error.ErrorDescription)
            : WwwAuthenticate.Challenge(TokenTypes.Bearer, realm);

    /// <summary>
    /// Builds a <c>WWW-Authenticate: Basic</c> challenge per RFC 7617 §2 for client-authentication
    /// failures (RFC 6749 §5.2). Only the realm parameter is emitted: unlike Bearer (RFC 6750 §3),
    /// the Basic scheme defines no error attributes, so the error itself stays in the JSON body.
    /// </summary>
    public static string BuildBasicChallenge(string? realm)
        => WwwAuthenticate.Challenge(TokenTypes.Basic, realm);

    /// <summary>
    /// Builds a <c>WWW-Authenticate: DPoP</c> challenge per RFC 9449 §7.1, advertising the
    /// JWS algorithms the AS accepts on a proof.
    /// </summary>
    public static string BuildDPoPChallenge(OidcError error, string? realm, IEnumerable<string> algs)
        // RFC 6750 §3.1 applies to the DPoP line too: an unauthenticated request gets a bare
        // challenge advertising the scheme, without error attributes. "algs" is DPoP's own parameter
        // (RFC 9449 §7.1) and is passed through the same grammar as the rest - the figure there prints
        // it as the FIRST parameter of a challenge with no realm, where the separator is a space.
        => error is MissingAuthenticationError
            ? WwwAuthenticate.Challenge(
                TokenTypes.DPoP,
                ("realm", realm),
                ("algs", string.Join(' ', algs)))
            : WwwAuthenticate.Challenge(
                TokenTypes.DPoP,
                ("realm", realm),
                ("error", error.Error),
                ("error_description", error.ErrorDescription),
                ("algs", string.Join(' ', algs)));

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
}
