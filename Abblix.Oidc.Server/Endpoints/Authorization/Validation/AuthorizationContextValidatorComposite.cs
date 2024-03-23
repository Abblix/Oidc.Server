// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Represents a composite validator for authorization contexts.
/// This class implements <see cref="IAuthorizationContextValidator"/> and aggregates multiple
/// validation steps into a single validation process.
/// </summary>
public class AuthorizationContextValidatorComposite : IAuthorizationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationContextValidatorComposite"/> class
    /// with a set of validation steps.
    /// </summary>
    /// <param name="validators">An array of validators that define the validation process.</param>
    public AuthorizationContextValidatorComposite(IAuthorizationContextValidator[] validators)
    {
        _validators = validators;
    }

    /// <summary>
    /// The array of validators representing the steps in the validation process.
    /// </summary>
    private readonly IAuthorizationContextValidator[] _validators;

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
        foreach (var validator in _validators)
        {
            var error = await validator.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
