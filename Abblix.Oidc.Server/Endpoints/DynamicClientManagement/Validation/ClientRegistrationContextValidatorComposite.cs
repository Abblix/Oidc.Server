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
/// This class represents a composite validator for client registration requests.
/// It aggregates multiple validation steps and executes them sequentially.
/// </summary>
/// <param name="validationSteps">The array of validation steps to be executed.</param>
public class ClientRegistrationContextValidatorComposite(IClientRegistrationContextValidator[] validationSteps) : IClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the client registration request by executing each validation step in the specified order.
    /// </summary>
    /// <param name="context">The validation context containing client registration information.</param>
    /// <returns>A AuthError if any validation step fails, or null if the request is valid.</returns>
    public async Task<AuthError?> ValidateAsync(ClientRegistrationValidationContext context)
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
