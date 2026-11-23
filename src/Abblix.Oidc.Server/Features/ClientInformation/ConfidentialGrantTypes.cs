// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The grant types that issue tokens on the client's word alone, which a client proving nothing never holds: a
/// registration, an update, a tenant's settings and a client metadata document keep them from a public client, and
/// the token endpoint refuses a public client asking for one.
/// </summary>
/// <remarks>
/// RFC 6749 section 4.4 says the client credentials grant "MUST only be used by confidential clients", and section
/// 4.4.2 "The client MUST authenticate with the authorization server". The resource owner password grant and the JWT
/// bearer grant are held to the same rule by this server's choice: neither involves an end user at the authorization
/// server, so a client authenticating with <c>none</c> would be issued tokens by anybody knowing its identifier.
/// </remarks>
internal static class ConfidentialGrantTypes
{
    private static readonly string[] All = [GrantTypes.ClientCredentials, GrantTypes.Password, GrantTypes.JwtBearer];

    /// <summary>
    /// The grant types of <paramref name="grantTypes"/> a client authenticating at the token endpoint with
    /// <paramref name="tokenEndpointAuthMethod"/> may not hold: these grant types for a public client, none for a
    /// confidential one.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">The client's token endpoint authentication method.</param>
    /// <param name="grantTypes">The grant types the client holds or asks for.</param>
    public static string[] RefusedTo(string tokenEndpointAuthMethod, IEnumerable<string> grantTypes)
        => ClientInfo.ClientTypeOf(tokenEndpointAuthMethod) switch
        {
            ClientType.Public => grantTypes.Intersect(All, StringComparer.Ordinal).ToArray(),
            ClientType.Confidential => [],
            var clientType => throw new InvalidOperationException(
                $"Unexpected {nameof(ClientType)}: {clientType}"),
        };
}
