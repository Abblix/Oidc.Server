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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Composite that runs the configured chain of <see cref="IClientRegistrationContextValidator"/>
/// steps in order and short-circuits on the first failure, mirroring RFC 7591 §3.2.2 which
/// requires the server to reject a registration on the first invalid metadata field.
/// </summary>
/// <param name="validationSteps">The validation steps to execute, in order.</param>
public class ClientRegistrationContextValidatorComposite(IClientRegistrationContextValidator[] validationSteps) : IClientRegistrationContextValidator
{
    /// <summary>
    /// Runs each step until one returns an error or all succeed.
    /// </summary>
    /// <param name="context">The shared validation context.</param>
    /// <returns>The first error produced, or <c>null</c> when every step passes.</returns>
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        foreach (var validationStep in validationSteps)
        {
            var error = await validationStep.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
