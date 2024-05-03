// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
