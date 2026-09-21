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
    /// Whether the client declared this claim essential, which OpenID Connect Core 1.0 section 5.5.1 defines
    /// as what the relying party tells the end user: releasing it "will ensure a smooth authorization for the
    /// specific task requested by the End-User". The same section forbids answering with an error when the
    /// claim is not returned, essential or voluntary alike, unless the description of that specific claim says
    /// otherwise - so this is not a condition a response has to meet. The claims whose description does
    /// say otherwise are <c>sub</c>, whose mismatch fails the authentication, <c>auth_time</c>, which this
    /// server writes on every ID token, and <c>acr</c>, under section 5.5.1.1.
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
