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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Manages the processing of token requests according to OAuth 2.0 and OpenID Connect specifications.
/// This includes validating the request for compliance with the protocol requirements and processing it to issue,
/// renew or exchange tokens as appropriate.
/// </summary>
public class TokenHandler : ITokenHandler
{
    /// <summary>
    /// Constructs a new instance of the <see cref="TokenHandler"/> with specified validator and processor
    /// for handling token requests.
    /// </summary>
    /// <param name="validator">An implementation of <see cref="ITokenRequestValidator"/> responsible for ensuring
    /// that token requests meet the required validation criteria.</param>
    /// <param name="processor">An implementation of <see cref="ITokenRequestProcessor"/> responsible for executing
    /// the logic necessary to issue, renew, or exchange tokens based on validated requests.</param>
    public TokenHandler(ITokenRequestValidator validator, ITokenRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly ITokenRequestValidator _validator;
    private readonly ITokenRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles a token request by first validating it and then, if the validation is successful,
    /// processing the request to issue, renew, or exchange tokens as required by the request parameters.
    /// </summary>
    /// <param name="tokenRequest">An object containing the details of the token request, including the grant type,
    /// client credentials and other necessary parameters.</param>
    /// <param name="clientRequest">Additional information about the client making the request, used for contextual
    /// validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="Interfaces.TokenResponse"/>, indicating the outcome of
    /// the request handling. This response can include the issued tokens in case of success, or an error response
    /// detailing the reason for failure if the request does not pass validation or cannot be processed.
    /// </returns>
    /// <remarks>
    /// This method is integral to the security and functionality of the OAuth 2.0 and OpenID Connect framework,
    /// ensuring that only valid and authorized requests result in the issuance, renewal, or exchange of tokens.
    /// It employs rigorous validation to prevent unauthorized access and to maintain the integrity of the token
    /// lifecycle management process.
    /// </remarks>
    public async Task<Result<TokenIssued, TokenError>> HandleAsync(
        TokenRequest tokenRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(tokenRequest, clientRequest);

        return await validationResult.MatchAsync(
            onSuccess: _processor.ProcessAsync,
            onFailure: error => Task.FromResult<Result<TokenIssued, TokenError>>(
                new TokenError(error.ErrorCode, error.ErrorDescription)));
    }
}
