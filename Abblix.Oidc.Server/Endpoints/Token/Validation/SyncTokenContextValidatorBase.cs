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

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Provides a base class for implementing synchronous token context validators.
/// This class simplifies the creation of token context validators by offering a synchronous validation method
/// that is automatically wrapped in an asynchronous call.
/// </summary>
public abstract class SyncTokenContextValidatorBase : ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the token request within the provided context by invoking the synchronous
    /// <see cref="Validate(TokenValidationContext)"/> method.
    /// </summary>
    /// <param name="context">
    /// The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="RequestError"/> containing error details
    /// if the validation fails;
    /// otherwise, resolves to null indicating that the validation was successful.
    /// </returns>
    public Task<RequestError?> ValidateAsync(TokenValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Validates the token request within the provided context. This method must be implemented by derived classes
    /// to perform the specific validation logic.
    /// </summary>
    /// <param name="context">
    /// The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="RequestError"/> containing error details if the validation fails;
    /// otherwise, returns null indicating that the validation was successful.
    /// </returns>
    protected abstract RequestError? Validate(TokenValidationContext context);
}
