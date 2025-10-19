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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Adapter class that implements <see cref="IAuthorizationRequestFetcher"/> to delegate the
/// fetching and processing of request objects to an instance of <see cref="IRequestObjectFetcher"/>.
/// </summary>
public class RequestObjectFetchAdapter : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObjectFetchAdapter"/> class.
    /// </summary>
    /// <param name="requestObjectFetcher">The request object fetcher responsible for fetching and processing
    /// the JWT request object.</param>
    public RequestObjectFetchAdapter(IRequestObjectFetcher requestObjectFetcher)
    {
        _requestObjectFetcher = requestObjectFetcher;
    }

    private readonly IRequestObjectFetcher _requestObjectFetcher;

    /// <summary>
    /// Fetches and processes the authorization request by delegating to the request object fetcher.
    /// </summary>
    /// <param name="request">The authorization request to be processed.</param>
    /// <returns>
    /// A task that returns a <see cref="FetchResult"/>
    /// which either represents a successfully processed request or an error indicating issues with the request object.
    /// </returns>
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request)
    {
        var fetchResult = await _requestObjectFetcher.FetchAsync(request, request.Request);

        if (fetchResult.TryGetSuccess(out var authorizationRequest))
            return authorizationRequest;

        if (fetchResult.TryGetFailure(out var error))
            return ErrorFactory.ValidationError(error.ErrorCode, error.ErrorDescription);

        throw new InvalidOperationException("Unexpected result state");
    }
}
