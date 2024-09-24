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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the user's identity in a backchannel authentication request, ensuring that valid identity hints
/// (e.g., login hints, tokens) are provided and correctly processed.
/// </summary>
public class UserIdentityValidator: IBackChannelAuthenticationContextValidator
{
    public UserIdentityValidator(
        IAuthServiceJwtValidator idTokenValidator,
        IClientJwtValidator clientJwtValidator)
    {
        _idTokenValidator = idTokenValidator;
        _clientJwtValidator = clientJwtValidator;
    }

    private readonly IAuthServiceJwtValidator _idTokenValidator;
    private readonly IClientJwtValidator _clientJwtValidator;

    /// <summary>
    /// Validates the user's identity based on the available identity hints (e.g., login hint, login hint token, ID token hint).
    /// It ensures that only one hint is present, and processes the provided hint to establish the user's identity.
    /// </summary>
    /// <param name="context">The validation context containing the backchannel authentication request.</param>
    /// <returns>
    /// A <see cref="BackChannelAuthenticationValidationError"/> if the identity validation fails,
    /// or null if the identity is successfully validated.
    /// </returns>
    public async Task<BackChannelAuthenticationValidationError?> ValidateAsync(
        BackChannelAuthenticationValidationContext context)
    {
        var request = context.Request;

        // Count the number of identity hints provided (LoginHint, LoginHintToken, IdTokenHint)
        var userIdentityCount = new[]
            {
                request.LoginHint,
                request.LoginHintToken,
                request.IdTokenHint,
            }
            .Count(id => id.HasValue());

        // Ensure exactly one identity hint is provided
        switch (userIdentityCount)
        {
            case 1:
                break; // Valid scenario

            case 0:
                return new BackChannelAuthenticationValidationError(
                    ErrorCodes.InvalidRequest, "The user's identity is unknown.");

            default:
                return new BackChannelAuthenticationValidationError(
                    ErrorCodes.InvalidRequest,
                    "User identity is not determined due to conflicting hints.");
        }

        // Validate the LoginHintToken if present and configured to parse as JWT
        if (request.LoginHintToken.HasValue() && context.ClientInfo.ParseLoginHintTokenAsJwt)
        {
            var (loginHintTokenResult, clientInfo) = await _clientJwtValidator.ValidateAsync(request.LoginHintToken);
            switch (loginHintTokenResult, clientInfo)
            {
                // Successful validation and the client matches
                case (ValidJsonWebToken { Token: var loginHintToken }, { ClientId: var clientId})
                    when clientId == context.ClientInfo.ClientId:

                    context.LoginHintToken = loginHintToken;
                    break;

                // The token was issued for another client
                case (ValidJsonWebToken, not null):

                    return new BackChannelAuthenticationValidationError(
                        ErrorCodes.InvalidRequest,
                        "LoginHintToken issued by another client.");

                // JWT validation failed
                case (JwtValidationError, _):
                    return new BackChannelAuthenticationValidationError(
                        ErrorCodes.InvalidRequest,
                        "LoginHintToken validation failed.");

                default:
                    throw new InvalidOperationException("Something went wrong.");
            }
        }

        // Validate the IdTokenHint if present
        if (request.IdTokenHint.HasValue())
        {
            var idTokenResult = await ValidateIdTokenHint(context, request.IdTokenHint);
            switch (idTokenResult)
            {
                case OperationResult<JsonWebToken>.Success(var idToken):
                    context.IdToken = idToken;
                    break;

                case OperationResult<JsonWebToken>.Error(var error, var description):
                    return new BackChannelAuthenticationValidationError(error, description);
            }
        }

        return null; // Identity validation successful
    }

    /// <summary>
    /// Validates the ID token hint to ensure it is properly issued and valid.
    /// </summary>
    /// <param name="context">The validation context containing the client information.</param>
    /// <param name="idTokenHint">The ID token hint string to be validated.</param>
    /// <returns>
    /// An <see cref="OperationResult{JsonWebToken}"/> representing the validation result,
    /// which can either be a successful token or an error.
    /// </returns>
    private async Task<OperationResult<JsonWebToken>> ValidateIdTokenHint(
        BackChannelAuthenticationValidationContext context,
        string idTokenHint)
    {
        // Validate the ID token hint but skip lifetime validation
        var result = await _idTokenValidator.ValidateAsync(
            idTokenHint,
            ValidationOptions.Default & ~ValidationOptions.ValidateLifetime);

        // Check if the token was issued for the correct client
        switch (result)
        {
            case ValidJsonWebToken { Token.Payload.Audiences: var audiences }
                when !audiences.Contains(context.ClientInfo.ClientId, StringComparer.Ordinal):

                return InvalidRequest(
                    "The id token hint contains token issued for the client other than specified");

            case JwtValidationError:
                return InvalidRequest("The id token hint contains invalid token");

            case ValidJsonWebToken { Token: var idToken }:
                return idToken;

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }

        // Helper method to generate an error response for invalid requests
        OperationResult<JsonWebToken>.Error InvalidRequest(string description)
            => new (ErrorCodes.InvalidRequest, description);
    }
}
