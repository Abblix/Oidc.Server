// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Manages the processing of token requests according to OAuth 2.0 and OpenID Connect specifications.
/// This includes validating the request for compliance with the protocol requirements and processing it to issue,
/// renew or exchange tokens as appropriate.
/// </summary>
/// <param name="validator">An implementation of <see cref="ITokenRequestValidator"/> responsible for ensuring
/// that token requests meet the required validation criteria.</param>
/// <param name="processor">An implementation of <see cref="ITokenRequestProcessor"/> responsible for executing
/// the logic necessary to issue, renew, or exchange tokens based on validated requests.</param>
public class TokenHandler(ITokenRequestValidator validator, ITokenRequestProcessor processor) : ITokenHandler
{
    /// <summary>
    /// Asynchronously handles a token request by first validating it and then, if the validation is successful,
    /// processing the request to issue, renew, or exchange tokens as required by the request parameters.
    /// </summary>
    /// <param name="tokenRequest">An object containing the details of the token request, including the grant type,
    /// client credentials and other necessary parameters.</param>
    /// <param name="clientRequest">Additional information about the client making the request, used for contextual
    /// validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="TokenIssued"/>, indicating the outcome of
    /// the request handling. The success response includes the issued tokens, while an <see cref="OidcError"/>
    /// details the reason for failure if the request does not pass validation or cannot be processed.
    /// </returns>
    /// <remarks>
    /// This method is integral to the security and functionality of the OAuth 2.0 and OpenID Connect framework,
    /// ensuring that only valid and authorized requests result in the issuance, renewal, or exchange of tokens.
    /// It employs rigorous validation to prevent unauthorized access and to maintain the integrity of the token
    /// lifecycle management process.
    /// </remarks>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<Result<TokenIssued, OidcError>> HandleAsync(
        TokenRequest tokenRequest,
        ClientRequest clientRequest,
        CancellationToken cancellationToken)
    {
        var validationResult = await validator.ValidateAsync(tokenRequest, clientRequest, cancellationToken);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
