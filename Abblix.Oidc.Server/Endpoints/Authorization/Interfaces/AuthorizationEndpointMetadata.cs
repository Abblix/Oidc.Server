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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Holds metadata for the authorization endpoint, detailing the capabilities and supported standards.
/// </summary>
public record AuthorizationEndpointMetadata
{
    /// <summary>
    /// Indicates whether the 'request' parameter of an authorization request is supported.
    /// This parameter is used for passing a request object by value.
    /// </summary>
    public bool RequestParameterSupported { get; init; }

    /// <summary>
    /// Indicates whether the claims parameter is supported for requesting specific claims.
    /// </summary>
    public bool ClaimsParameterSupported { get; init; }

    /// <summary>
    /// The response types the authorization server supports.
    /// </summary>
    public List<string> ResponseTypesSupported { get; init; } =
    [
        ResponseTypes.Code,
        ResponseTypes.Token,
        ResponseTypes.IdToken,
        string.Join(' ', ResponseTypes.Code, ResponseTypes.Token),
        string.Join(' ', ResponseTypes.Code, ResponseTypes.IdToken),
        string.Join(' ', ResponseTypes.Token, ResponseTypes.IdToken),
        string.Join(' ', ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken)
    ];

    /// <summary>
    /// The response modes the authorization server supports for returning parameters from the authorization endpoint.
    /// </summary>
    public List<string> ResponseModesSupported { get; init; } =
    [
        ResponseModes.Query,
        ResponseModes.Fragment,
        ResponseModes.FormPost
    ];

    /// <summary>
    /// The prompt values the authorization server supports for interaction with the end-user.
    /// </summary>
    public List<string> PromptValuesSupported { get; init; } =
    [
        Prompts.SelectAccount,
        Prompts.Consent,
        Prompts.None,
        Prompts.Login,
        Prompts.Create
    ];

    /// <summary>
    /// The code challenge methods supported for PKCE (Proof Key for Code Exchange).
    /// </summary>
    public List<string> CodeChallengeMethodsSupported { get; init; } =
    [
        CodeChallengeMethods.S512,
        CodeChallengeMethods.S256,
        CodeChallengeMethods.Plain
    ];
}
