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
/// Represents a composite validator for token context validation, executing a sequence of individual validators.
/// This class allows multiple validators to be combined, each responsible for a specific validation step,
/// and short-circuits the validation process if any step fails.
/// </summary>
public class TokenContextValidatorComposite : ITokenContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenContextValidatorComposite"/> class
    /// with the specified array of validators.
    /// </summary>
    /// <param name="validators">An array of validators representing the steps in the validation process.</param>
    public TokenContextValidatorComposite(ITokenContextValidator[] validators)
    {
        _validators = validators;
    }

    /// <summary>
    /// The array of validators that will be executed in sequence during the validation process.
    /// </summary>
    private readonly ITokenContextValidator[] _validators;

    /// <summary>
    /// Asynchronously validates the token request by executing each validator in the sequence.
    /// The validation process stops at the first encountered error and returns it.
    /// If all validators succeed, the method returns null, indicating successful validation.
    /// </summary>
    /// <param name="context">The context containing the token request and related information
    /// that needs to be validated.</param>
    /// <returns>
    /// A <see cref="RequestError"/> containing error details if any validation step fails;
    /// otherwise, returns null indicating that all validation steps were successful.
    /// </returns>
    public async Task<RequestError?> ValidateAsync(TokenValidationContext context)
    {
        foreach (var validator in _validators)
        {
            var error = await validator.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
