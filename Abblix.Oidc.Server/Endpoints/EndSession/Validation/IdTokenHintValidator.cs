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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Validates the ID token hint in the context of an end-session request.
/// This validator checks if the ID token hint provided in the request is valid and matches the expected audience (client).
/// </summary>
public class IdTokenHintValidator : IEndSessionContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IdTokenHintValidator"/> class.
    /// </summary>
    /// <param name="jwtValidator">The JWT validator used to validate ID tokens.</param>
    public IdTokenHintValidator(IAuthServiceJwtValidator jwtValidator)
    {
        _jwtValidator = jwtValidator;
    }

    private readonly IAuthServiceJwtValidator _jwtValidator;

    /// <summary>
    /// Validates the ID token hint.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>An error if validation fails, null if successful.</returns>
    public async Task<RequestError?> ValidateAsync(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (request.IdTokenHint.HasValue())
        {
            var result = await _jwtValidator.ValidateAsync(
                request.IdTokenHint,
                ValidationOptions.Default & ~ValidationOptions.ValidateLifetime);

            switch (result)
            {
                case ValidJsonWebToken { Token: var idToken, Token.Payload.Audiences: var audiences }:
                    if (!request.ClientId.HasValue())
                    {
                        try
                        {
                            context.ClientId = audiences.Single();
                        }
                        catch (Exception)
                        {
                            return new RequestError(
                                ErrorCodes.InvalidRequest,
                                "The audience in the id token hint is missing or have multiple values.");
                        }
                    }
                    else if (!audiences.Contains(request.ClientId, StringComparer.Ordinal))
                    {
                        return new RequestError(
                            ErrorCodes.InvalidRequest,
                            "The id token hint contains token issued for the client other than specified");
                    }

                    context.IdToken = idToken;
                    break;

                case JwtValidationError:
                    return new RequestError(ErrorCodes.InvalidRequest,
                        "The id token hint contains invalid token");

                default:
                    throw new UnexpectedTypeException(nameof(result), result.GetType());
            }
        }

        return null;
    }
}
