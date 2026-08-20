// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// This property is used when a particular value for the claim is required for processing.
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
