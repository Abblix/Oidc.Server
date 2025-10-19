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

using Abblix.Utils;
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
    public async Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(
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

        if (result.TryGetSuccess(out var validRequest))
        {
            var clientId = validRequest.Model.ClientId;
            var redirectUri = validRequest.Model.RedirectUri;
            var responseMode = validRequest.ResponseMode;

            if (clientInfo.ClientId != clientId)
            {
                return new AuthorizationRequestValidationError(
                    ErrorCodes.InvalidRequest,
                    "The pushed authorization request must be bound to the client that posted it",
                    redirectUri,
                    responseMode);
            }
        }

        return result;
    }
}
