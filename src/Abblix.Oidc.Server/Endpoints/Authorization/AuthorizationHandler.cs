// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Handles authorization requests by fetching, validating, processing and encoding the response.
/// </summary>
/// <param name="fetcher">Resolves the effective authorization request, including dereferencing pushed
/// (RFC 9126) or request-object (OIDC Core section 6) variants.</param>
/// <param name="validator">Performs protocol-level validation of the resolved request prior to processing.</param>
/// <param name="processor">Produces the validated authorization result projected onto the wire.</param>
/// <param name="responseEncoder">Applies iss/scope gating and, for a JARM request, packs the response
/// parameters into the response JWT, at the single convergence point for success and every error variant.</param>
public class AuthorizationHandler(
    IAuthorizationRequestFetcher fetcher,
    IAuthorizationRequestValidator validator,
    IAuthorizationRequestProcessor processor,
    IAuthorizationResponseEncoder responseEncoder)
    : IAuthorizationHandler
{
    /// <summary>
    /// Asynchronously handles an authorization request by first fetching the request if necessary,
    /// validating the request and then processing it to generate an authorization response.
    /// </summary>
    /// <param name="request">The authorization request to be handled. This can be a direct request or a reference
    /// to an external request that needs to be fetched.</param>
    /// <returns>A task that returns an <see cref="AuthorizationResponse"/>.
    /// This response can be either an authorization success response or an error response based on the fetching,
    /// validation and processing outcomes.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result is of an unexpected type.</exception>
    /// <remarks>
    /// The handling process involves three main steps:
    /// 1. Fetching of the authorization request if specified by a request or request_uri parameter.
    /// 2. Validation of the authorization request against predefined criteria to ensure its legitimacy and completeness.
    /// 3. Processing of the validated request to generate an authorization response, which could involve user
    ///    authentication, consent handling, and token issuance.
    ///
    /// This method ensures that only requests meeting the necessary validation criteria are processed,
    /// maintaining the integrity and security of the authorization flow.
    /// </remarks>
    public async Task<AuthorizationResponse> HandleAsync(Model.AuthorizationRequest request)
    {
        // Produce the response through the full processing chain (including the session-management
        // decorator that sets session_state), then let the encoder apply iss/scope gating and - for a
        // JARM request - pack the parameters into the response JWT. Encoding happens here, at the single
        // convergence point for success and every error variant, after session_state is finalised.
        var response = await ProduceResponseAsync(request);
        await responseEncoder.EncodeAsync(response);
        return response;
    }

    private async Task<AuthorizationResponse> ProduceResponseAsync(Model.AuthorizationRequest request)
    {
        var fetchResult = await fetcher.FetchAsync(request);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(request, fetchError);

        request = fetchResult.GetSuccess();

        var validationResult = await validator.ValidateAsync(request);

        return await validationResult.MatchAsync(
            onSuccess: processor.ProcessAsync,
            onFailure: error => Task.FromResult<AuthorizationResponse>(new AuthorizationError(request, error)));
    }
}
