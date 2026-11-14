// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Parameters of a request to the OIDC <c>userinfo_endpoint</c> (OIDC Core section 5.3). The access token
/// is normally presented in the HTTP <c>Authorization</c> header per RFC 6750 section 2.1, but RFC 6750 sections 2.2
/// and 2.3 also permit the <c>access_token</c> parameter in the form-encoded body and in the URI query, modeled here
/// as one member per source.
/// </summary>
[ExternalInput]
public record UserInfoRequest
{
    /// <summary>
    /// Wire-level parameter names accepted at the OIDC UserInfo endpoint (OIDC Core section 5.3,
    /// RFC 6750 section 2 token transport).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>access_token</c> parameter carrying the bearer access token when the client
        /// submits it in the request body or the URI query rather than the <c>Authorization</c> header
        /// (RFC 6750 sections 2.2 and 2.3).</summary>
        public const string AccessToken = "access_token";
    }

    /// <summary>
    /// The access token sent in the URI query (RFC 6750 section 2.3). Kept apart from
    /// <see cref="AccessTokenInForm"/> because a security profile refuses this source alone: FAPI 2.0 Security
    /// Profile section 5.3.4 forbids it and says nothing of the body.
    /// </summary>
    [JsonIgnore]
    [QueryParameter(Parameters.AccessToken)]
    [Credential]
    public string? AccessTokenInQuery { get; set; }

    /// <summary>
    /// The access token sent in the form-encoded body (RFC 6750 section 2.2).
    /// </summary>
    [JsonIgnore]
    [FormParameter(Parameters.AccessToken)]
    [Credential]
    public string? AccessTokenInForm { get; set; }

    /// <summary>
    /// The access token the request carries as a parameter, from the body or else the query. Read here by whoever
    /// does not care where it traveled. Computed rather than bound, so neither host binds nor serializes it.
    /// </summary>
    [JsonIgnore]
    [Credential]
    public string? AccessToken => AccessTokenInForm ?? AccessTokenInQuery;
}
