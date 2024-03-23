// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common.Implementation;

/// <summary>
/// Provides claim names based on requested scopes and claims.
/// </summary>
public class ScopeClaimsProvider : IScopeClaimsProvider
{
    private readonly Dictionary<string, string[]> _scopeToClaimsMap = new[]
    {
        StandardScopes.OpenId,
        StandardScopes.Profile,
        StandardScopes.Email,
        StandardScopes.Address,
        StandardScopes.Phone,
        StandardScopes.OfflineAccess,
    }.ToDictionary(definition => definition.Scope, definition => definition.ClaimTypes, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the requested claims based on scopes and requested claim details.
    /// </summary>
    /// <param name="scopes">An array of requested scopes.</param>
    /// <param name="requestedClaims">A dictionary of requested claim details.</param>
    /// <returns>Enumeration of claim names.</returns>
    public IEnumerable<string> GetRequestedClaims(
        IEnumerable<string> scopes,
        Dictionary<string, RequestedClaimDetails>? requestedClaims)
    {
        var claimNames = scopes
            .SelectMany(scope => _scopeToClaimsMap.TryGetValue(scope, out var claimsInScope) ? claimsInScope : Array.Empty<string>())
            .Prepend(JwtClaimTypes.Subject);

        if (requestedClaims != null)
        {
            claimNames = claimNames.Concat(
                from claim in requestedClaims
                where claim.Value.Essential == true
                select claim.Key);
        }

        return claimNames;
    }

    /// <summary>
    /// A collection of all the scopes supported by this provider.
    /// </summary>
    public IEnumerable<string> ScopesSupported => _scopeToClaimsMap.Keys;

    /// <summary>
    /// A collection of all the claims that can be provided by this provider.
    /// </summary>
    public IEnumerable<string> ClaimsSupported => _scopeToClaimsMap.Values.SelectMany(claims => claims);
}
