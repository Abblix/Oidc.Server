// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Implements the <see cref="IScopeClaimsProvider"/> interface to provide claim names based on requested scopes
/// and claims. This class manages the association between scopes and the specific claims they include,
/// facilitating the retrieval of appropriate claims for given scopes during the authorization process.
/// </summary>
/// <param name="scopeManager">The scope manager used to look up scope definitions.</param>
public class ScopeClaimsProvider(IScopeManager scopeManager) : IScopeClaimsProvider
{
    /// <summary>
    /// Retrieves the specific claims associated with the requested scopes and any additional requested claims.
    /// </summary>
    /// <param name="scopes">The collection of scopes for which claims need to be provided.</param>
    /// <param name="requestedClaims">Additional specific claims requested outside of the scope requests.</param>
    /// <returns>A collection of claim names that are associated with the requested scopes and additional claims.
    /// </returns>
    public IEnumerable<string> GetRequestedClaims(
        IEnumerable<string> scopes,
        IEnumerable<string>? requestedClaims)
    {
        var claimNames = scopes
            .SelectMany(scope => scopeManager.TryGet(scope, out var scopeDefinition)
                ? scopeDefinition.ClaimTypes
                : [])
            .Prepend(JwtClaimTypes.Subject);

        if (requestedClaims != null)
        {
            claimNames = claimNames.Concat(requestedClaims);
        }

        return claimNames;
    }

    /// <summary>
    /// A collection of all the scopes supported by this provider.
    /// </summary>
    public IEnumerable<string> ScopesSupported
        => scopeManager.Select(def => def.Scope);

    /// <summary>
    /// A collection of all the claims that can be provided by this provider.
    /// </summary>
    public IEnumerable<string> ClaimsSupported
        => scopeManager.SelectMany(def => def.ClaimTypes).Distinct(StringComparer.Ordinal);
}
