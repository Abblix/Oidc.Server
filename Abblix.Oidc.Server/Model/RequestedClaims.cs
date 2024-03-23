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

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents claims requested for inclusion in the UserInfo response and ID Token in OAuth2 or OpenID Connect authentication flows.
/// </summary>
public record RequestedClaims
{
    /// <summary>
    /// A collection of claims requested to be included in the UserInfo response.
    /// Each entry in the dictionary represents a claim with its corresponding details, such as whether the claim is essential and specific value requirements.
    /// </summary>
    [JsonPropertyName("userinfo")]
    public Dictionary<string, RequestedClaimDetails>? UserInfo { get; init; }

    /// <summary>
    /// A collection of claims requested to be included in the ID Token.
    /// Similar to UserInfo, each entry in the dictionary specifies a claim and its associated details, including essentiality and value constraints.
    /// </summary>
    [JsonPropertyName("id_token")]
    public Dictionary<string, RequestedClaimDetails>? IdToken { get; init; }
}
