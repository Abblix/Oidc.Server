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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Represents a composite validator for authorization contexts.
/// This class implements <see cref="IAuthorizationContextValidator"/> and aggregates multiple
/// validation steps into a single validation process.
/// </summary>
/// <param name="validators">An array of validators that define the validation process.</param>
public class AuthorizationContextValidatorComposite(IAuthorizationContextValidator[] validators) : IAuthorizationContextValidator
{
    /// <summary>
    /// Asynchronously validates an <see cref="AuthorizationValidationContext"/>.
    /// Iterates through each validation step, returning the first encountered error, if any.
    /// </summary>
    /// <param name="context">The authorization validation context to be validated.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation. The task result contains
    /// an <see cref="AuthorizationRequestValidationError"/> if a validation error is found, or null if validation succeeds.
    /// </returns>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        foreach (var validator in validators)
        {
            var error = await validator.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
