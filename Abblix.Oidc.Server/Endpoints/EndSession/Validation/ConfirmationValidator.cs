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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents a validator for end-session requests requiring user confirmation.
/// </summary>
public class ConfirmationValidator:  IEndSessionContextValidator
{
    /// <summary>
    /// Validates the end-session request for confirmation.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>A task representing the asynchronous operation.
    /// The result is a validation error if confirmation is missing; otherwise, null.</returns>
    public Task<EndSessionRequestValidationError?> ValidateAsync(EndSessionValidationContext context)
        => Task.FromResult(Validate(context));

    private static EndSessionRequestValidationError? Validate(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (request.Confirmed != true && !request.IdTokenHint.HasValue())
        {
            return new EndSessionRequestValidationError(
                ErrorCodes.ConfirmationRequired,
                "The request requires to be confirmed by user");
        }

        return null;
    }
}
