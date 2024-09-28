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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Serves as the base class for handling the fetching and processing of request objects,
/// including JWT validation and binding JSON payloads to request models.
/// </summary>
public abstract class RequestObjectFetcherBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObjectFetcherBase"/> class, providing necessary services
    /// for logging, JSON binding, and client key retrieval.
    /// </summary>
    /// <param name="logger">The logger for recording debug information and warnings.</param>
    /// <param name="jsonObjectBinder">The binder for converting JSON payloads into request objects.</param>
    /// <param name="serviceProvider">The service provider used for resolving dependencies at runtime.</param>
    protected RequestObjectFetcherBase(
        ILogger<RequestObjectFetcherBase> logger,
        IJsonObjectBinder jsonObjectBinder,
        IServiceProvider serviceProvider)
    {
        _logger = logger;
        _jsonObjectBinder = jsonObjectBinder;
        _serviceProvider = serviceProvider;
    }

    private readonly ILogger _logger;
    private readonly IJsonObjectBinder _jsonObjectBinder;
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Fetches and processes the request object by validating its JWT and binding the payload to the request model.
    /// </summary>
    /// <typeparam name="T">The type of the request model.</typeparam>
    /// <param name="request">The initial request model to bind the JWT payload to.</param>
    /// <param name="requestObject">The JWT contained within the request, if any.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains an <see cref="Result{T}"/>
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is used to decode and validate the JWT contained in the request. If the JWT is valid, the payload
    /// is bound to the request model. If the JWT is invalid, an error is returned and logged.
    /// </remarks>
    protected async Task<Result<T>> FetchAsync<T>(T request, string? requestObject)
        where T : class
    {
        if (!requestObject.HasValue())
            return request;

        _logger.LogDebug("JWT request object was: {RequestObject}", requestObject);

        JwtValidationResult? result;
        using (var scope = _serviceProvider.CreateScope())
        {
            var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();
            (result, _) = await tokenValidator.ValidateAsync(
                requestObject, ValidationOptions.ValidateIssuerSigningKey);
        }

        switch (result)
        {
            case ValidJsonWebToken { Token.Payload.Json: var payload }:
                var updatedRequest = await _jsonObjectBinder.BindModelAsync(payload, request);
                if (updatedRequest == null)
                    return InvalidRequestObject("Unable to bind request object");

                return updatedRequest;

            case JwtValidationError error:
                _logger.LogWarning("The request object contains invalid token: {@Error}", error);
                return InvalidRequestObject("The request object is invalid.");

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }

        static Result<T>.Error InvalidRequestObject(string description)
            => new(ErrorCodes.InvalidRequestObject, description);
    }
}
