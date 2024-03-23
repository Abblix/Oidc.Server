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
    public List<string> ResponseTypesSupported { get; init; } = new()
    {
        ResponseTypes.Code,
        ResponseTypes.Token,
        ResponseTypes.IdToken,
        string.Join(' ', ResponseTypes.Code, ResponseTypes.Token),
        string.Join(' ', ResponseTypes.Code, ResponseTypes.IdToken),
        string.Join(' ', ResponseTypes.Token, ResponseTypes.IdToken),
        string.Join(' ', ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken),
    };

    /// <summary>
    /// The response modes the authorization server supports for returning parameters from the authorization endpoint.
    /// </summary>
    public List<string> ResponseModesSupported { get; init; } = new()
    {
        ResponseModes.Query,
        ResponseModes.Fragment,
        ResponseModes.FormPost,
    };

    /// <summary>
    /// The prompt values the authorization server supports for interaction with the end-user.
    /// </summary>
    public List<string> PromptValuesSupported { get; init; } = new()
    {
        Prompts.SelectAccount,
        Prompts.Consent,
        Prompts.None,
        Prompts.Login,
        Prompts.Create,
    };

    /// <summary>
    /// The code challenge methods supported for PKCE (Proof Key for Code Exchange).
    /// </summary>
    public List<string> CodeChallengeMethodsSupported { get; init; } = new()
    {
        CodeChallengeMethods.S256,
        CodeChallengeMethods.Plain,
    };
}
