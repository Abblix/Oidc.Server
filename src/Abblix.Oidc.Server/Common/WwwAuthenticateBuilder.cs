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
/// Builds <c>WWW-Authenticate</c> challenge values for the Bearer scheme (RFC 6750 section 3)
/// and the DPoP scheme (RFC 9449 section 7.1). Endpoint-agnostic and framework-agnostic so the
/// same emission logic serves UserInfo, introspection, revocation, and any future
/// protected endpoint, regardless of whether the host is ASP.NET Core MVC, minimal APIs,
/// or another framework altogether.
/// </summary>
/// <remarks>
/// Where both schemes are advertised, RFC 9449 section 7.2 decides which challenge carries the error: "If no
/// authentication information has been included with the request, then the challenges SHOULD NOT include an error code
/// or other error information", "If the mechanism used to attempt authentication could be established unambiguously,
/// then the corresponding challenge SHOULD be used to deliver error information", and "Otherwise, both Bearer and DPoP
/// challenges MAY be used to deliver error information". The mechanism is <see cref="OidcError.PresentedScheme"/>.
/// </remarks>
public static class WwwAuthenticateBuilder
{
    private const string RealmAttribute = "realm";
    private const string ErrorAttribute = "error";
    private const string ErrorDescriptionAttribute = "error_description";
    private const string ScopeAttribute = "scope";
    private const string AlgorithmsAttribute = "algs";

    /// <summary>
    /// Builds a <c>WWW-Authenticate: Bearer</c> challenge per RFC 6750 section 3. The <c>error</c>,
    /// <c>error_description</c> and <c>scope</c> attributes are emitted unless <paramref name="includeError"/> is
    /// <c>false</c>, which a dual-scheme response passes for the challenge of the scheme the client did not use.
    /// </summary>
    public static string BuildBearerChallenge(OidcError error, string? realm, bool includeError = true)
        // RFC 6750 section 3.1: when the request carried no authentication information at all, the
        // challenge must stay bare - no error code or description, just the scheme (and realm).
        => includeError && error is not MissingAuthenticationError
            ? WwwAuthenticate.Challenge(
                TokenTypes.Bearer,
                (RealmAttribute, realm),
                (ErrorAttribute, error.Error),
                (ErrorDescriptionAttribute, error.ErrorDescription),
                (ScopeAttribute, error.RequiredScope))
            : WwwAuthenticate.Challenge(TokenTypes.Bearer, realm);

    /// <summary>
    /// Builds a <c>WWW-Authenticate: Basic</c> challenge per RFC 7617 section 2 for client-authentication
    /// failures (RFC 6749 section 5.2). Only the realm parameter is emitted: unlike Bearer (RFC 6750 section 3),
    /// the Basic scheme defines no error attributes, so the error itself stays in the JSON body.
    /// </summary>
    public static string BuildBasicChallenge(string? realm)
        => WwwAuthenticate.Challenge(TokenTypes.Basic, realm);

    /// <summary>
    /// Builds a <c>WWW-Authenticate: DPoP</c> challenge per RFC 9449 section 7.1, advertising the
    /// JWS algorithms the AS accepts on a proof. The <c>error</c>, <c>error_description</c> and <c>scope</c>
    /// attributes are emitted unless <paramref name="includeError"/> is <c>false</c>, which a dual-scheme response
    /// passes for the challenge of the scheme the client did not use.
    /// </summary>
    public static string BuildDPoPChallenge(
        OidcError error,
        string? realm,
        IEnumerable<string> algs,
        bool includeError = true)
        // RFC 6750 section 3.1 applies to the DPoP line too: an unauthenticated request gets a bare
        // challenge advertising the scheme, without error attributes. "algs" is DPoP's own parameter
        // (RFC 9449 Section 7.1) and is passed through the same grammar as the rest - the figure there prints
        // it as the FIRST parameter of a challenge with no realm, where the separator is a space.
        => includeError && error is not MissingAuthenticationError
            ? WwwAuthenticate.Challenge(
                TokenTypes.DPoP,
                (RealmAttribute, realm),
                (ErrorAttribute, error.Error),
                (ErrorDescriptionAttribute, error.ErrorDescription),
                (ScopeAttribute, error.RequiredScope),
                (AlgorithmsAttribute, string.Join(' ', algs)))
            : WwwAuthenticate.Challenge(
                TokenTypes.DPoP,
                (RealmAttribute, realm),
                (AlgorithmsAttribute, string.Join(' ', algs)));

    /// <summary>
    /// Builds the full set of <c>WWW-Authenticate</c> challenge lines for an error
    /// response. Returns DPoP first, Bearer second when both schemes are advertised, the error on the challenge of the
    /// scheme <see cref="OidcError.PresentedScheme"/> names, or on both where it names none.
    /// </summary>
    public static IReadOnlyList<string> BuildChallenges(
        OidcError error,
        string? realm,
        IEnumerable<string> dpopAlgs,
        bool advertiseBearer)
    {
        // A resource admitting no proof algorithm, where the client's profile refuses DPoP, does not offer the scheme.
        // A sole challenge carries the error whichever scheme was used, since there is no other to deliver it
        var algorithms = dpopAlgs.ToArray();
        if (algorithms.Length == 0 && advertiseBearer)
            return [BuildBearerChallenge(error, realm)];

        if (!advertiseBearer)
            return [BuildDPoPChallenge(error, realm, algorithms)];

        var (onDPoP, onBearer) = error.PresentedScheme switch
        {
            AccessTokenScheme.DPoP => (true, false),
            AccessTokenScheme.Bearer => (false, true),
            null => (true, true),
            _ => throw new ArgumentOutOfRangeException(
                nameof(error), error.PresentedScheme, "The scheme the access token was presented with is unknown"),
        };

        return
        [
            BuildDPoPChallenge(error, realm, algorithms, includeError: onDPoP),
            BuildBearerChallenge(error, realm, includeError: onBearer),
        ];
    }
}
