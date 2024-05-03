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
