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

using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents a composite validator for end-session requests.
/// </summary>
public class EndSessionContextValidatorComposite : IEndSessionContextValidator
{
    /// <summary>
    /// Initializes a new instance of this class with an array of validation steps.
    /// </summary>
    /// <param name="validationSteps">The array of end-session context validators to execute.</param>
    public EndSessionContextValidatorComposite(IEndSessionContextValidator[] validationSteps)
    {
        _validationSteps = validationSteps;
    }

    private readonly IEndSessionContextValidator[] _validationSteps;

    /// <summary>
    /// Validates the end-session request using a composite of multiple validators.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>A task representing the asynchronous operation.
    /// The result is a validation error if any validation step fails; otherwise, null.</returns>
    public async Task<EndSessionRequestValidationError?> ValidateAsync(EndSessionValidationContext context)
    {
        foreach (var validationStep in _validationSteps)
        {
            var error = await validationStep.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
