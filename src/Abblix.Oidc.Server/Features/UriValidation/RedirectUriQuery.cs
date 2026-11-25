// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// The query of a client's redirect URI, the one rule the check of the settings, dynamic registration, client ID
/// metadata documents and the authorization endpoint hold it to.
/// </summary>
internal static class RedirectUriQuery
{
    /// <summary>
    /// The parameters this server adds to a redirect URI in an authorization response.
    /// </summary>
    internal static readonly FrozenSet<string> ResponseParameters = FrozenSet.Create(
        StringComparer.Ordinal,
        AuthorizationResponse.Parameters.State,
        AuthorizationResponse.Parameters.Code,
        AuthorizationResponse.Parameters.TokenType,
        AuthorizationResponse.Parameters.AccessToken,
        AuthorizationResponse.Parameters.ExpiresIn,
        AuthorizationResponse.Parameters.IdToken,
        AuthorizationResponse.Parameters.Error,
        AuthorizationResponse.Parameters.ErrorDescription,
        AuthorizationResponse.Parameters.ErrorUri,
        AuthorizationResponse.Parameters.Scope,
        AuthorizationResponse.Parameters.SessionState,
        AuthorizationResponse.Parameters.Issuer,
        AuthorizationResponse.Parameters.Response);

    /// <summary>
    /// The first parameter of an authorization response the query of <paramref name="uri"/> names, or null where it names
    /// none. OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 2.3: "The query string component MUST NOT include any
    /// parameters defined for use in the authorization response", which would reach the client beside the ones the
    /// server adds, or in their place. A name is compared as it reads once decoded, so an encoded spelling of one is the
    /// same parameter.
    /// </summary>
    /// <param name="uri">An absolute URI.</param>
    public static string? ResponseParameterIn(Uri uri)
    {
        var query = uri.Query.TrimStart('?');
        if (query.Length == 0)
            return null;

        foreach (var pair in query.Split('&'))
        {
            var separator = pair.IndexOf('=');
            var name = Uri.UnescapeDataString((separator < 0 ? pair : pair[..separator]).Replace('+', ' '));
            if (ResponseParameters.Contains(name))
                return name;
        }

        return null;
    }
}
