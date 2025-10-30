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
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the user's identity in a backchannel authentication request, ensuring that valid identity hints
/// (e.g., login hints, tokens) are provided and correctly processed.
/// </summary>
/// <param name="idTokenValidator">Validator for ID tokens issued by the authorization server.</param>
/// <param name="clientJwtValidator">Validator for JWTs issued by clients.</param>
public class UserIdentityValidator(
    IAuthServiceJwtValidator idTokenValidator,
    IClientJwtValidator clientJwtValidator): IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Validates the user's identity based on the provided identity hints, such as login hint, login hint token,
    /// or ID token hint. It ensures that only one identity hint is present and attempts to process the hint
    /// to confirm the user's identity.
    /// </summary>
    /// <param name="context">Contains the backchannel authentication request and client information.</param>
    /// <returns>
    /// Returns a <see cref="OidcError"/> if the identity validation fails,
    /// or null if the identity is successfully validated.
    /// </returns>
    public async Task<OidcError?> ValidateAsync(
        BackChannelAuthenticationValidationContext context)
    {
        var request = context.Request;

        // Count the number of identity hints (LoginHint, LoginHintToken, IdTokenHint) provided in the request
        var userIdentityCount = new[]
            {
                request.LoginHint,        // Regular login hint
                request.LoginHintToken,   // JWT-based login hint token
                request.IdTokenHint       // ID token hint provided by the client
            }
            .Count(id => id.HasValue());

        switch (userIdentityCount)
        {
            case 1:
                break; // Valid scenario: exactly one hint is provided

            case 0:
                // No identity hint is present; return an error indicating the user's identity is unknown
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The user's identity is unknown.");

            default:
                // Multiple identity hints provided; return an error indicating ambiguity
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "User identity is not determined due to conflicting hints.");
        }

        // Validate the LoginHintToken if it is provided and the client is configured to parse it as a JWT
        if (request.LoginHintToken.HasValue() && context.ClientInfo.ParseLoginHintTokenAsJwt)
        {
            var (loginHintTokenResult, clientInfo) = await clientJwtValidator.ValidateAsync(request.LoginHintToken);
            switch (loginHintTokenResult, clientInfo)
            {
                // The token was issued for another client
                case (ValidJsonWebToken, { ClientId: var clientId})
                    when clientId != context.ClientInfo.ClientId:

                    return new OidcError(
                        ErrorCodes.InvalidRequest,
                        "LoginHintToken issued by another client.");

                // If the token is valid and issued for the correct client, store it in the validation context
                case (ValidJsonWebToken { Token: var loginHintToken }, _):
                    context.LoginHintToken = loginHintToken;
                    break;

                case (JwtValidationError { Error: JwtError.InvalidToken }, _):
                    break;

                // If JWT validation fails, return an error
                case (JwtValidationError, _):
                    return new OidcError(
                        ErrorCodes.InvalidRequest,
                        "LoginHintToken validation failed.");

                // Unexpected cases should result in an exception
                default:
                    throw new InvalidOperationException("Something went wrong.");
            }
        }

        // Validate the IdTokenHint if present
        if (request.IdTokenHint.HasValue())
        {
            var idTokenResult = await ValidateIdTokenHint(context, request.IdTokenHint);
            if (idTokenResult.TryGetFailure(out var error))
            {
                return new OidcError(error.Error, error.ErrorDescription);
            }

            context.IdToken = idTokenResult.GetSuccess();
        }

        return null; // Identity validation successful
    }

    /// <summary>
    /// Validates the ID token hint to ensure it is properly issued and valid.
    /// </summary>
    /// <param name="context">The validation context containing the client information.</param>
    /// <param name="idTokenHint">The ID token hint string to be validated.</param>
    /// <returns>
    /// An <see cref="Result{JsonWebToken, AuthError}"/> representing the validation result,
    /// which can either be a successful token or an error.
    /// </returns>
    private async Task<Result<JsonWebToken, OidcError>> ValidateIdTokenHint(
        BackChannelAuthenticationValidationContext context,
        string idTokenHint)
    {
        var result = await idTokenValidator.ValidateAsync(
            idTokenHint,
            ValidationOptions.Default & ~ValidationOptions.ValidateLifetime);

        return result switch
        {
            ValidJsonWebToken { Token.Payload.Audiences: var audiences }
                when !audiences.Contains(context.ClientInfo.ClientId, StringComparer.Ordinal)
                => new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The id token hint contains token issued for the client other than specified"),

            JwtValidationError
                => new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The id token hint contains invalid token"),

            ValidJsonWebToken { Token: var idToken }
                => idToken,

            _ => throw new UnexpectedTypeException(nameof(result), result.GetType()),
        };
    }
}
