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
    /// <remarks>
    /// Deliberately not constrained by a declarative value list: the core composite grant handler
    /// rejects an unregistered grant with the protocol-level unsupported grant type error.
    /// </remarks>
    [BindProperty(Name = Parameters.GrantType)]
    [Required]
    public required string GrantType { get; set; }

    /// <summary>
    /// The authorization code received from the authorization server.
    /// This is used in the authorization code grant type to exchange the code for an access token.
    /// </summary>
    [BindProperty(Name = Parameters.Code)]
    public string? Code { get; set; }

    /// <summary>
    /// The URI where the client will be redirected after authorization.
    /// This is used in conjunction with the authorization code grant type.
    /// </summary>
    [BindProperty(Name = Parameters.RedirectUri)]
    public Uri? RedirectUri { get; set; }

    /// <summary>
    /// Specifies the resource for which the access token is requested.
    /// As defined in RFC 8707, this parameter is used to request access tokens with a specific scope for a particular resource.
    /// </summary>
    [BindProperty(Name = Parameters.Resource)]
    public Uri[]? Resource { get; set; }

    /// <summary>
    /// The refresh token used to obtain a new access token.
    /// This is applicable in scenarios where the client already holds a refresh token and requires a new access token.
    /// </summary>
    [BindProperty(Name = Parameters.RefreshToken)]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Array of scope values indicating the permissions the client is requesting.
    /// Scopes specify the level of access required and the associated permissions.
    /// </summary>
    [BindProperty(Name = Parameters.Scope)]
    [ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[] Scope { get; set; } = [];

    /// <summary>
    /// The username of the resource owner, used in the password grant type.
    /// This represents the credentials of the user for whom the client is requesting the token.
    /// </summary>
    [BindProperty(Name = Parameters.Username)]
    public string? UserName { get; set; }

    /// <summary>
    /// The password of the resource owner, used in the password grant type.
    /// Along with the username, this forms the user credentials required for the password grant type.
    /// </summary>
    [BindProperty(Name = Parameters.Password)]
    public string? Password { get; set; }

    /// <summary>
    /// The code verifier for Proof Key for Code Exchange (PKCE) used in the authorization code grant type.
    /// This is used to mitigate authorization code interception attacks.
    /// </summary>
    [BindProperty(Name = Parameters.CodeVerifier)]
    public string? CodeVerifier { get; set; }

    /// <summary>
    /// The authentication request identifier for Client Initiated Backchannel Authentication (CIBA).
    /// This is used in the CIBA grant type to reference a previously initiated authentication request.
    /// </summary>
    [BindProperty(Name = Parameters.AuthenticationRequestId)]
    public string? AuthenticationRequestId { get; set; }

    /// <summary>RFC 8693 §2.1 <c>subject_token</c> -- the security token being exchanged.</summary>
    [BindProperty(Name = Parameters.SubjectToken)]
    public string? SubjectToken { get; set; }

    /// <summary>RFC 8693 §2.1 <c>subject_token_type</c> -- the type URI of the subject token.</summary>
    [BindProperty(Name = Parameters.SubjectTokenType)]
    public string? SubjectTokenType { get; set; }

    /// <summary>RFC 8693 §2.1 <c>actor_token</c> -- optional security token representing the acting party.</summary>
    [BindProperty(Name = Parameters.ActorToken)]
    public string? ActorToken { get; set; }

    /// <summary>RFC 8693 §2.1 <c>actor_token_type</c> -- the type URI of the actor token, required when <c>actor_token</c> is present.</summary>
    [BindProperty(Name = Parameters.ActorTokenType)]
    public string? ActorTokenType { get; set; }

    /// <summary>RFC 8693 §2.1 <c>requested_token_type</c> -- optional indicator of the token type the client would like to receive.</summary>
    [BindProperty(Name = Parameters.RequestedTokenType)]
    public string? RequestedTokenType { get; set; }

    /// <summary>RFC 8693 §2.1 <c>audience</c> -- optional logical name(s) of the relying party. Repeated wire parameter binds to an array.</summary>
    [BindProperty(Name = Parameters.Audience)]
    public string[]? Audiences { get; set; }

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
            Resources = Resource,
            Scope = Scope,
            RefreshToken = RefreshToken,
            RedirectUri = RedirectUri,
            CodeVerifier = CodeVerifier,
            AuthenticationRequestId = AuthenticationRequestId,
            SubjectToken = SubjectToken,
            SubjectTokenType = SubjectTokenType,
            ActorToken = ActorToken,
            ActorTokenType = ActorTokenType,
            RequestedTokenType = RequestedTokenType,
            Audiences = Audiences,
        };
    }
}
