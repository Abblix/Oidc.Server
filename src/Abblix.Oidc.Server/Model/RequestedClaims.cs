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
/// Represents claims requested for inclusion in the UserInfo response and ID Token in OAuth2 or OpenID Connect authentication flows.
/// </summary>
public record RequestedClaims
{
    /// <summary>
    /// A collection of claims requested to be included in the UserInfo response.
    /// Each entry in the dictionary represents a claim with its corresponding details,
    /// such as whether the claim is essential and specific value requirements.
    /// </summary>
    [JsonPropertyName(Parameters.UserInfo)]
    public Dictionary<string, RequestedClaimDetails>? UserInfo { get; init; }

    /// <summary>
    /// A collection of claims requested to be included in the ID Token.
    /// Similar to UserInfo, each entry in the dictionary specifies a claim and its associated details,
    /// including essentiality and value constraints.
    /// </summary>
    [JsonPropertyName(Parameters.IdToken)]
    public Dictionary<string, RequestedClaimDetails>? IdToken { get; init; }

    /// <summary>
    /// Wire-level member names of the OIDC Core 1.0 section 5.5 <c>claims</c> request parameter
    /// (the top-level <c>userinfo</c> / <c>id_token</c> objects within it).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>userinfo</c> top-level member naming the claims the client wants
        /// the UserInfo endpoint to return.</summary>
        public const string UserInfo = "userinfo";

        /// <summary>The <c>id_token</c> top-level member naming the claims the client wants
        /// embedded in the issued ID Token.</summary>
        public const string IdToken = "id_token";
    }
}
