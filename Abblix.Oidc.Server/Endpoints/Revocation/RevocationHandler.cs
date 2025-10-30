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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// Manages the handling of token revocation requests in accordance with OAuth 2.0 specifications, ensuring that such
/// requests are properly validated and processed to revoke tokens as intended.
/// </summary>
public class RevocationHandler : IRevocationHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RevocationHandler"/> class with the necessary validator and
    /// processor for revocation requests.
    /// </summary>
    /// <param name="validator">
    /// An implementation of <see cref="IRevocationRequestValidator"/> responsible for validating the revocation request
    /// against the OAuth 2.0 specifications.</param>
    /// <param name="processor">
    /// An implementation of <see cref="IRevocationRequestProcessor"/> responsible for processing validated revocation
    /// requests to effectively revoke tokens.</param>
    public RevocationHandler(
        IRevocationRequestValidator validator,
        IRevocationRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IRevocationRequestValidator _validator;
    private readonly IRevocationRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles a token revocation request by validating it and then processing it if the
    /// validation succeeds.
    /// </summary>
    /// <param name="revocationRequest">
    /// The revocation request details, mapped to the model expected by the system.</param>
    /// <param name="clientRequest">
    /// Additional client request information that may be necessary for validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="Result{TSuccess, TFailure}"/> containing either
    /// <see cref="TokenRevoked"/> on success or <see cref="AuthError"/> on failure.
    /// </returns>
    /// <remarks>
    /// This method plays a critical role in maintaining the security and integrity of the OAuth 2.0 ecosystem
    /// by allowing tokens to be revoked when they are no longer needed or when a security issue necessitates
    /// their invalidation. It ensures that revocation requests are thoroughly vetted before any action is taken,
    /// preventing unauthorized or malicious attempts to revoke tokens.
    /// </remarks>
    public async Task<Result<TokenRevoked, AuthError>> HandleAsync(
        RevocationRequest revocationRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(revocationRequest, clientRequest);

        return await validationResult.MatchAsync(
            onSuccess: _processor.ProcessAsync,
            onFailure: error => Task.FromResult<Result<TokenRevoked, AuthError>>(error));
    }
}
