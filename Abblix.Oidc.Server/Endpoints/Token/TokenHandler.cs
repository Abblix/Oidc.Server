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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Model;
using TokenResponse = Abblix.Oidc.Server.Endpoints.Token.Interfaces.TokenResponse;

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
    public async Task<TokenResponse> HandleAsync(
        TokenRequest tokenRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(tokenRequest, clientRequest);

        var response = validationResult switch
        {
            ValidTokenRequest validRequest => await _processor.ProcessAsync(validRequest),

            TokenRequestError { Error: var error, ErrorDescription: var description }
                => new TokenErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType())
        };
        return response;
    }
}
