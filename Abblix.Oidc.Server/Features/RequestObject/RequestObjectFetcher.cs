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
/// <param name="logger">The logger for recording debug information and warnings.</param>
/// <param name="jsonObjectBinder">The binder for converting JSON payloads into request objects.</param>
/// <param name="serviceProvider">The service provider used for resolving dependencies at runtime.</param>
/// <param name="options">Options that define how request object validation is handled, including whether
/// request objects must be signed.</param>
public class RequestObjectFetcher(
    ILogger<RequestObjectFetcher> logger,
    IJsonObjectBinder jsonObjectBinder,
    IServiceProvider serviceProvider,
    IOptionsSnapshot<OidcOptions> options) : IRequestObjectFetcher
{
    /// <summary>
    /// Fetches and processes the request object by validating its JWT and binding the payload to the request model.
    /// </summary>
    /// <typeparam name="T">The type of the request model.</typeparam>
    /// <param name="request">The initial request model to bind the JWT payload to.</param>
    /// <param name="requestObject">The JWT contained within the request, if any.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains an <see cref="Result{T, AuthError}"/>
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is used to decode and validate the JWT contained in the request. If the JWT is valid, the payload
    /// is bound to the request model. If the JWT is invalid, an error is returned and logged.
    /// </remarks>
    public async Task<Result<T, OidcError>> FetchAsync<T>(T request, string? requestObject)
        where T : class
    {
        if (!requestObject.HasValue())
            return request;

        var validationResult = await ValidateAsync(requestObject);
        return await validationResult.BindAsync<T>(
            async payload =>
            {
                var updatedRequest = await jsonObjectBinder.BindModelAsync(payload, request);
                if (updatedRequest == null)
                    return InvalidRequestObject("Unable to bind request object");

                return updatedRequest;
            }
        );
    }

    /// <summary>
    /// Validates the JWT request object to ensure it complies with the required signing algorithm
    /// and structure, based on the OIDC options.
    /// </summary>
    /// <param name="requestObject">The JWT request object to be validated.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{JsonObject, AuthError}"/>
    /// indicating whether the JWT is valid or contains errors.
    /// </returns>
    /// <remarks>
    /// This method uses the configured OIDC options to determine whether the JWT must be signed and validates
    /// it accordingly. It retrieves a validator service from the DI container to perform the validation.
    /// </remarks>
    private async Task<Result<JsonObject, OidcError>> ValidateAsync(string requestObject)
    {
        // Always validate issuer when present (but accept missing issuer)
        // Always validate signatures when present (ValidateIssuerSigningKey)
        // Always validate lifetime (exp/nbf claims) if present
        // Only require signed tokens when RequireSignedRequestObject is true
        var validationOptions = ValidationOptions.ValidateIssuer |
                                ValidationOptions.ValidateIssuerSigningKey |
                                ValidationOptions.ValidateLifetime;

        if (options.Value.RequireSignedRequestObject)
            validationOptions |= ValidationOptions.RequireSignedTokens;

        using var scope = serviceProvider.CreateScope();
        var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();
        var result = await tokenValidator.ValidateAsync(requestObject, validationOptions);

        return result.Match<Result<JsonObject, OidcError>>(
            validJwt => validJwt.Token.Payload.Json,
            error => InvalidRequestObject(error));
    }

    private OidcError InvalidRequestObject(JwtValidationError error)
    {
        logger.LogWarning("The request object contains invalid token: {@Error}", error);
        return new OidcError(ErrorCodes.InvalidRequestObject, "The request object is invalid.");
    }

    private static OidcError InvalidRequestObject(string description)
        => new(ErrorCodes.InvalidRequestObject, description);
}
