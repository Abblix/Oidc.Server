// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// The one answer to which cutoffs refuse a grant redeemed from a session authenticated in an earlier request, asked
/// by the token endpoint and by CIBA push completion, which mints without the client coming to that endpoint.
/// </summary>
internal static class RevocationCutoffCheckerExtensions
{
    /// <summary>
    /// Whether a cutoff refuses the grant: one recorded against its session or its subject, or, for a grant the end
    /// user authorized at its client, one recorded against them at that client.
    /// </summary>
    /// <remarks>
    /// A refresh token is left to its own issue time at the client: the token side already refuses one issued
    /// before such a cutoff, while its grant carries no authorization moment and would be measured against its
    /// session, refusing a family founded after the end user consented again in that same session.
    /// </remarks>
    /// <param name="cutoffChecker">Reads the cutoffs.</param>
    /// <param name="grant">The grant being redeemed.</param>
    /// <param name="grantType">The grant type it is redeemed under.</param>
    public static async Task<bool> IsGrantRefusedAsync(
        this IRevocationCutoffChecker cutoffChecker, AuthorizedGrant grant, string grantType)
    {
        if (await cutoffChecker.IsSessionRefusedAsync(grant.AuthSession))
            return true;

        switch (grantType)
        {
            case GrantTypes.RefreshToken:
                return false;

            case GrantTypes.AuthorizationCode or GrantTypes.DeviceAuthorization or GrantTypes.Ciba:
                return await cutoffChecker.IsGrantRefusedAtItsClientAsync(grant);

            default:
                throw new InvalidOperationException($"No revocation check is defined for the grant type {grantType}");
        }
    }
}
