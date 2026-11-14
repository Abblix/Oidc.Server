// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Handles the processing of Pushed Authorization Requests (PAR) by validating the requests and then processing
/// them if valid. This class acts as an intermediary between the validation and processing stages of the PAR workflow.
/// </summary>
/// <param name="clientAuthenticator">Authenticates the client before anything it sent is read.</param>
/// <param name="fetcher">
/// An instance of <see cref="IAuthorizationRequestFetcher"/> used to resolve <c>request</c> /
/// <c>request_uri</c> JAR payloads before validation.</param>
/// <param name="validator">An instance of <see cref="IPushedAuthorizationRequestValidator"/> used for validating
/// pushed authorization requests.</param>
/// <param name="processor">An instance of <see cref="IPushedAuthorizationRequestProcessor"/> used for processing
/// validated authorization requests.</param>
public class PushedAuthorizationHandler(
    IClientAuthenticator clientAuthenticator,
    IAuthorizationRequestFetcher fetcher,
    IPushedAuthorizationRequestValidator validator,
    IPushedAuthorizationRequestProcessor processor) : IPushedAuthorizationHandler
{
    /// <summary>
    /// Asynchronously handles a pushed authorization request by first validating it and then processing it if
    /// the validation is successful.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
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
        TenantDefinition tenant,
        Model.AuthorizationRequest authorizationRequest,
        Model.ClientRequest clientRequest)
    {
        // RFC 9126 section 2.1: "The authorization server MUST process the request as follows: 1. Authenticate the client
        // in the same way as at the token endpoint". Done before the request object is read, so the object is held to
        // the authenticated client's security profile before any layer of it is decrypted
        var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(tenant, clientRequest);
        if (clientInfo == null)
            return new AuthorizationError(authorizationRequest, ErrorFactory.InvalidClient("The client is not authorized"));

        // The object is read for the client the request names, which has to be the one that authenticated
        if (authorizationRequest.ClientId is { } named && named != clientInfo.ClientId)
        {
            return new AuthorizationError(
                authorizationRequest,
                ErrorFactory.InvalidRequest("The pushed authorization request must be bound to the client that posted it"));
        }

        // RFC 9126 section 3: "Request parameters required by a given client authentication method are included in the
        // "application/x-www-form-urlencoded" request directly and are the only parameters other than "request" in the
        // form body". A client whose authentication method carries no client_id in the form sends the object alone, so
        // the client it authenticated as is the one the object is read for. A form of plain parameters has no such
        // exemption: section 2.1 has client_id "similarly required in a pushed authorization request"
        var fetchResult = await fetcher.FetchAsync(
            tenant,
            authorizationRequest is { Request: not null, ClientId: null }
                ? authorizationRequest with { ClientId = clientInfo.ClientId }
                : authorizationRequest);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(authorizationRequest, fetchError);

        // RFC 9126 section 2.1 forbids request_uri in a pushed request, and strict request object processing rebuilds
        // the request from the object alone, so the one sent beside the object is carried on for the validator to refuse
        var fetched = fetchResult.GetSuccess();
        authorizationRequest = fetched with { RequestUri = fetched.RequestUri ?? authorizationRequest.RequestUri };

        var validationResult = await validator.ValidateAsync(tenant, clientInfo, authorizationRequest, clientRequest);

        return await validationResult.MatchAsync(
            onSuccess: valid => processor.ProcessAsync(tenant, valid),
            onFailure: error => Task.FromResult<AuthorizationResponse>(
                new AuthorizationError(authorizationRequest, error)));
    }
}
