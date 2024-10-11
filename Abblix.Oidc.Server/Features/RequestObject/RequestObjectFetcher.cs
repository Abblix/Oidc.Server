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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Provides functionality to validate and process JWT request objects, binding their payloads to a request model.
/// This class is typically used in OpenID Connect flows where request parameters are passed as JWTs.
/// </summary>
public class RequestObjectFetcher : IRequestObjectFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObjectFetcher"/> class, providing necessary services
    /// for logging, JSON binding, and client key retrieval.
    /// </summary>
    /// <param name="logger">The logger for recording debug information and warnings.</param>
    /// <param name="jsonObjectBinder">The binder for converting JSON payloads into request objects.</param>
    /// <param name="serviceProvider">The service provider used for resolving dependencies at runtime.</param>
    /// <param name="options">Options that define how request object validation is handled, including whether
    /// request objects must be signed.</param>
    public RequestObjectFetcher(
        ILogger<RequestObjectFetcher> logger,
        IJsonObjectBinder jsonObjectBinder,
        IServiceProvider serviceProvider,
        IOptionsSnapshot<OidcOptions> options)
    {
        _logger = logger;
        _jsonObjectBinder = jsonObjectBinder;
        _serviceProvider = serviceProvider;
        _options = options;
    }

    private readonly ILogger _logger;
    private readonly IJsonObjectBinder _jsonObjectBinder;
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptionsSnapshot<OidcOptions> _options;

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
    public async Task<Result<T>> FetchAsync<T>(T request, string? requestObject)
        where T : class
    {
        // Return original request if no request object is provided
        if (!requestObject.HasValue())
            return request;

        _logger.LogDebug("JWT request object was: {RequestObject}", requestObject);

        var result = await ValidateAsync(requestObject);
        switch (result)
        {
            // If the JWT is valid and contains a JSON payload, bind it to the request
            case Result<JsonObject>.Success(var payload):
                var updatedRequest = await _jsonObjectBinder.BindModelAsync(payload, request);
                if (updatedRequest == null)
                    return InvalidRequestObject<T>("Unable to bind request object");
                return updatedRequest;

            // Handle validation errors
            case Result<JsonObject>.Error(var error, var description):
                return new Result<T>.Error(error, description);

            // Handle unexpected result
            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }
    }

    /// <summary>
    /// Validates the JWT request object to ensure it complies with the required signing algorithm
    /// and structure, based on the OIDC options.
    /// </summary>
    /// <param name="requestObject">The JWT request object to be validated.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="JwtValidationResult"/>
    /// indicating whether the JWT is valid or contains errors.
    /// </returns>
    /// <remarks>
    /// This method uses the configured OIDC options to determine whether the JWT must be signed and validates
    /// it accordingly. It retrieves a validator service from the DI container to perform the validation.
    /// </remarks>
    private async Task<Result<JsonObject>> ValidateAsync(string requestObject)
    {
        // Set validation options, requiring the token to be signed if specified in the OIDC options
        var options = ValidationOptions.ValidateIssuerSigningKey;
        if (_options.Value.RequireSignedRequestObject)
            options |= ValidationOptions.RequireSignedTokens;

        // Use dependency injection to get a JWT validator and perform the validation
        using var scope = _serviceProvider.CreateScope();
        var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();
        var (result, _) = await tokenValidator.ValidateAsync(requestObject, options);

        switch (result)
        {
            // If the JWT is valid and contains a JSON payload, bind it to the request
            case ValidJsonWebToken { Token.Payload.Json: var payload }:
                return payload;

            // Log warning and return error result if JWT validation failed
            case JwtValidationError error:
                _logger.LogWarning("The request object contains invalid token: {@Error}", error);
                return InvalidRequestObject<JsonObject>("The request object is invalid.");

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }
    }

    private static Result<T>.Error InvalidRequestObject<T>(string description)
        => new(ErrorCodes.InvalidRequestObject, description);
}
