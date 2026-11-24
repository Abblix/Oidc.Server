// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// The mark of a session, and of every token issued from it, that the client credentials grant opens for the client
/// itself, with no end user behind it.
/// </summary>
/// <remarks>
/// The grant writes the mark into <see cref="AuthSession.IdentityProvider"/>, which every token issued from the session
/// carries as <c>idp</c>, and a token exchange carries on from its subject token. Each endpoint that answers only for
/// an end user, or shows a resource server which kind of token it holds (RFC 9700 section 4.15.1), asks here.
/// </remarks>
internal static class ClientCredentialsSession
{
    /// <summary>
    /// The identity provider of such a session.
    /// </summary>
    public const string IdentityProvider = GrantTypes.ClientCredentials;

    /// <summary>
    /// Whether a session or token with this identity provider is the client's own rather than an end user's.
    /// </summary>
    /// <param name="identityProvider">The session's identity provider, or a token's <c>idp</c> claim.</param>
    public static bool IsClientItself(string? identityProvider)
        => string.Equals(identityProvider, IdentityProvider, StringComparison.Ordinal);
}
