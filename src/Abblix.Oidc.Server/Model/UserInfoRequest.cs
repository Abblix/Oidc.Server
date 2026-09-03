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
/// Parameters of a request to the OIDC <c>userinfo_endpoint</c> (OIDC Core section 5.3). The access token
/// is normally presented in the HTTP <c>Authorization</c> header per RFC 6750 section 2.1, but RFC 6750 section 2.2
/// also permits the form-encoded <c>access_token</c> body parameter modeled here.
/// </summary>
public record UserInfoRequest
{
    /// <summary>
    /// Wire-level parameter names accepted at the OIDC UserInfo endpoint (OIDC Core section 5.3,
    /// RFC 6750 section 2 token transport).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>access_token</c> form parameter carrying the bearer access token when the
        /// client submits it in the request body rather than the <c>Authorization</c> header
        /// (RFC 6750 section 2.2).</summary>
        public const string AccessToken = "access_token";
    }

    /// <summary>
    /// The access token that authorizes the request to retrieve user information.
    /// This token is typically obtained during the authentication process and is used to access protected user data.
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public string? AccessToken { get; set; }
}
