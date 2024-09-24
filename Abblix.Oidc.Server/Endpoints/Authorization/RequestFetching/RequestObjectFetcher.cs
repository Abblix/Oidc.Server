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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Handles the fetching and processing of authorization request objects, which may include validating JWTs
/// and binding JSON payloads to <see cref="AuthorizationRequest"/> models.
/// </summary>
public class RequestObjectFetcher : RequestObjectFetcherBase, IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObjectFetcher"/> class, setting up dependencies
    /// for JWT validation, JSON binding, and client information retrieval.
    /// </summary>
    /// <param name="logger">
    /// Used for logging debug and warning messages during the fetching and validation processes.
    /// </param>
    /// <param name="jsonObjectBinder">
    /// Handles the conversion of JSON payloads into <see cref="AuthorizationRequest"/> objects.
    /// </param>
    /// <param name="serviceProvider">
    /// Provides access to service dependencies, enabling scope-based resolution of services.
    /// </param>
    public RequestObjectFetcher(
        ILogger<RequestObjectFetcher> logger,
        IJsonObjectBinder jsonObjectBinder,
        IServiceProvider serviceProvider)
        : base(logger, jsonObjectBinder, serviceProvider)
    {
    }

    /// <summary>
    /// Fetches and processes the authorization request object, including decoding and validating any embedded JWTs.
    /// The method binds the contents of a valid JWT to an updated <see cref="AuthorizationRequest"/>.
    /// </summary>
    /// <param name="request">
    /// The initial authorization request, which may contain a 'request' parameter with a JWT that encapsulates
    /// the full request details.
    /// </param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="FetchResult"/> which
    /// can be either a successfully processed <see cref="AuthorizationRequest"/> or an error result indicating
    /// validation issues.
    /// </returns>
    /// <remarks>
    /// This method decodes and validates the JWT contained in the 'request' parameter of the authorization request.
    /// Upon successful validation, it binds the JWT payload to the authorization request model.
    /// If the JWT is invalid, the method logs a warning and returns an error result encapsulated
    /// in a <see cref="FetchResult"/>.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        var fetchResult = await FetchAsync(request, request.Request);
        return fetchResult switch
        {
            OperationResult<AuthorizationRequest>.Success(var authorizationRequest) => authorizationRequest,

            OperationResult<AuthorizationRequest>.Error(var error, var description)
                => ErrorFactory.ValidationError(error, description),

            _ => throw new UnexpectedTypeException(nameof(fetchResult), fetchResult.GetType()),
        };
    }
}
