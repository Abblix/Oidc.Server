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

using System.ComponentModel.DataAnnotations;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.TokenRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a request for an OAuth 2.0 token, encapsulates various parameters used in different grant types
/// for obtaining tokens.
/// </summary>
public record TokenRequest
{
    /// <summary>
    /// Specifies the OAuth 2.0 grant type of the token request.
    /// This property defines the mechanism used to obtain the access token, such as authorization code, client credentials, or refresh token.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.GrantType)]
    [Required]
    [AllowedValues(
        GrantTypes.AuthorizationCode,
        GrantTypes.RefreshToken,
        GrantTypes.Password,
        GrantTypes.Ciba,
        GrantTypes.Implicit,
        GrantTypes.ClientCredentials)]
    public string GrantType { get; set; } = default!;

    /// <summary>
    /// The authorization code received from the authorization server.
    /// This is used in the authorization code grant type to exchange the code for an access token.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Code)]
    public string? Code { get; set; }

    /// <summary>
    /// The URI where the client will be redirected after authorization.
    /// This is used in conjunction with the authorization code grant type.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.RedirectUri)]
    public Uri? RedirectUri { get; set; }

    /// <summary>
    /// Specifies the resource for which the access token is requested.
    /// As defined in RFC 8707, this parameter is used to request access tokens with a specific scope for a particular resource.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Resource)]
    public Uri[]? Resource { get; set; }

    /// <summary>
    /// The refresh token used to obtain a new access token.
    /// This is applicable in scenarios where the client already holds a refresh token and requires a new access token.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.RefreshToken)]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Array of scope values indicating the permissions the client is requesting.
    /// Scopes specify the level of access required and the associated permissions.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Scope)]
    [AllowedValues(
        Scopes.OpenId,
        Scopes.Profile,
        Scopes.Email,
        Scopes.Phone,
        Scopes.OfflineAccess)]
    [ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[] Scope { get; set; } = Array.Empty<string>();

    /// <summary>
    /// The username of the resource owner, used in the password grant type.
    /// This represents the credentials of the user for whom the client is requesting the token.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Username)]
    public string? UserName { get; set; }

    /// <summary>
    /// The password of the resource owner, used in the password grant type.
    /// Along with the username, this forms the user credentials required for the password grant type.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Password)]
    public string? Password { get; set; }

    /// <summary>
    /// The code verifier for Proof Key for Code Exchange (PKCE) used in the authorization code grant type.
    /// This is used to mitigate authorization code interception attacks.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.CodeVerifier)]
    public string? CodeVerifier { get; set; }

    /// <summary>
    /// Maps the properties of this token request to a <see cref="Core.TokenRequest"/> object.
    /// This method is used to translate the request data into a format that can be processed by the core logic of the server.
    /// </summary>
    /// <returns>A <see cref="Core.TokenRequest"/> object populated with data from this request.</returns>
    public Core.TokenRequest Map()
    {
        return new Core.TokenRequest
        {
            GrantType = GrantType,
            Code = Code,
            Password = Password,
            Resource = Resource,
            Scope = Scope,
            RefreshToken = RefreshToken,
            RedirectUri = RedirectUri,
            CodeVerifier = CodeVerifier,
        };
    }
}
