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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Handles the processing of Pushed Authorization Requests (PAR) by validating the requests and then processing
/// them if valid. This class acts as an intermediary between the validation and processing stages of the PAR workflow.
/// </summary>
/// <param name="fetcher">э
/// An instance of <see cref="IAuthorizationRequestFetcher"/> used to retrieve request objects.</param>
/// <param name="validator">An instance of <see cref="IPushedAuthorizationRequestValidator"/> used for validating
/// pushed authorization requests.</param>
/// <param name="processor">An instance of <see cref="IPushedAuthorizationRequestProcessor"/> used for processing
/// validated authorization requests.</param>
public class PushedAuthorizationHandler(
    IAuthorizationRequestFetcher fetcher,
    IPushedAuthorizationRequestValidator validator,
    IPushedAuthorizationRequestProcessor processor) : IPushedAuthorizationHandler
{
    /// <summary>
    /// Asynchronously handles a pushed authorization request by first validating it and then processing it if
    /// the validation is successful.
    /// </summary>
    /// <param name="authorizationRequest">The authorization request details as received from the client.</param>
    /// <param name="clientRequest">Additional client request information that may be needed for contextual validation.
    /// </param>
    /// <returns>
    /// A <see cref="Task"/> that upon completion yields an <see cref="AuthorizationResponse"/>, which could be a
    /// successful response with the request being processed or an error response if the validation fails.
    /// </returns>
    /// <remarks>
    /// This method ensures that pushed authorization requests are thoroughly validated against the system's
    /// criteria before proceeding with processing. This validation includes, but is not limited to, verifying
    /// the client's identity, the request's integrity, and its compliance with the system's policies.
    /// Successful validation leads to the processing of the request, which typically involves generating a request URI
    /// or an error response in case of failure.
    /// </remarks>
    public async Task<AuthorizationResponse> HandleAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest)
    {
        var fetchResult = await fetcher.FetchAsync(authorizationRequest);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(authorizationRequest, fetchError);

        authorizationRequest = fetchResult.GetSuccess();

        var validationResult = await validator.ValidateAsync(authorizationRequest, clientRequest);

        return await validationResult.MatchAsync(
            onSuccess: processor.ProcessAsync,
            onFailure: error => Task.FromResult<AuthorizationResponse>(new AuthorizationError(
                authorizationRequest,
                error.Error,
                error.ErrorDescription,
                error.ResponseMode,
                error.RedirectUri)));
    }
}
