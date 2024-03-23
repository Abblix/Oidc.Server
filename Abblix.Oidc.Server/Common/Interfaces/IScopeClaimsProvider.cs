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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Represents a service responsible for mapping requested claims based on scopes and requested claim details.
/// </summary>
public interface IScopeClaimsProvider
{
    /// <summary>
    /// The requested claims based on scopes and requested claim details.
    /// </summary>
    /// <param name="scopes">The requested scopes.</param>
    /// <param name="requestedClaims">The requested claim details.</param>
    /// <returns>An IEnumerable of claim names.</returns>
    IEnumerable<string> GetRequestedClaims(IEnumerable<string> scopes, Dictionary<string, RequestedClaimDetails>? requestedClaims);

    /// <summary>
    /// A collection of all the scopes supported by this provider.
    /// </summary>
    IEnumerable<string> ScopesSupported { get; }

    /// <summary>
    /// A collection of all the claims that can be provided by this provider.
    /// </summary>
    IEnumerable<string> ClaimsSupported { get; }
}
