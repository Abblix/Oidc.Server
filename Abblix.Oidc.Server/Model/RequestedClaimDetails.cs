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
/// Represents the details of a requested claim in OAuth2 or OpenID Connect scenarios.
/// This can include whether the claim is essential, and specific values or a range of values for the claim.
/// </summary>
public record RequestedClaimDetails
{
    /// <summary>
    /// Indicates whether the claim is essential for the authorization process.
    /// If true, the claim is essential and should be provided by the user for successful authorization.
    /// </summary>
    [JsonPropertyName("essential")]
    public bool? Essential { get; init; }

    /// <summary>
    /// Specifies the specific value the claim should have.
    /// This property is used when a particular value for the claim is for processing.
    /// </summary>
    [JsonPropertyName("value")]
    public object? Value { get; init; }

    /// <summary>
    /// Specifies a set of acceptable values for the claim.
    /// This property is used when multiple values are acceptable for the claim.
    /// </summary>
    [JsonPropertyName("values")]
    public object[]? Values { get; init; }
}
