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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Model;
using static Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Validates pushed authorization requests by enforcing OAuth 2.0 protocol constraints.
/// This validator ensures that requests do not use prohibited parameters and
/// comply with standard authorization request requirements.
/// </summary>
public class PushedAuthorizationRequestValidator : IPushedAuthorizationRequestValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PushedAuthorizationRequestValidator"/> class.
    /// This validator is responsible for validating pushed authorization requests according to the OAuth 2.0 protocol.
    /// It ensures that the requests adhere to the required standards and do not include any prohibited parameters.
    /// </summary>
    /// <param name="authorizationRequestValidator">
    /// The <see cref="IAuthorizationRequestValidator"/> used to validate the standard parameters of authorization
    /// requests.
    /// </param>
    /// <param name="clientAuthenticator">
    /// The <see cref="IClientAuthenticator"/> used to authenticate the client making the pushed authorization request.
    /// </param>
    public PushedAuthorizationRequestValidator(
        IAuthorizationRequestValidator authorizationRequestValidator,
        IClientAuthenticator clientAuthenticator)
    {
        _authorizationRequestValidator = authorizationRequestValidator;
        _clientAuthenticator = clientAuthenticator;
    }

    private readonly IAuthorizationRequestValidator _authorizationRequestValidator;
    private readonly IClientAuthenticator _clientAuthenticator;

    /// <summary>
    /// Validates a pushed authorization request according to OAuth 2.0 and OpenID Connect standards.
    /// This method ensures that the request does not contain prohibited parameters like 'request_uri' and
    /// verifies that it adheres to the client's registered parameters. It effectively prevents misuse
    /// and ensures that the request is legitimately associated with the authenticated client.
    /// </summary>
    /// <param name="authorizationRequest">The authorization request to be validated.</param>
    /// <param name="clientRequest"></param>
    /// <returns>A task that resolves to a validation result, indicating whether the request is valid
    /// and adheres to the expected protocol constraints.</returns>
    public async Task<AuthorizationRequestValidationResult> ValidateAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest)
    {
        var clientInfo = await _clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
        if (clientInfo == null)
        {
            return ErrorFactory.InvalidClient("The client is not authorized");
        }

        if (authorizationRequest.RequestUri is not null)
        {
            return ErrorFactory.InvalidRequestUri(
                $"{RequestUri} is prohibited to use in pushed authorization request");
        }

        var result = await _authorizationRequestValidator.ValidateAsync(authorizationRequest);

        if (result is ValidAuthorizationRequest {
                Model: { ClientId: var clientId, RedirectUri: var redirectUri },
                ResponseMode: var responseMode
            } && clientInfo.ClientId != clientId)
        {
            return new AuthorizationRequestValidationError(

                ErrorCodes.InvalidRequest,
                "The pushed authorization request must be bound to the client that posted it",
                redirectUri,
                responseMode);
        }

        return result;
    }
}
