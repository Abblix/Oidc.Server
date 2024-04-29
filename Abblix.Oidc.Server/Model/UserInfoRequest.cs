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
/// Represents a request to retrieve user information, typically used in OpenID Connect flows.
/// Inherits from <see cref="ClientRequest"/>.
/// </summary>
public record UserInfoRequest
{
    public static class Parameters
    {
        public const string AccessToken = "access_token";
    }

    /// <summary>
    /// The access token that authorizes the request to retrieve user information.
    /// This token is typically obtained during the authentication process and is used to access protected user data.
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public string? AccessToken { get; set; }
}
