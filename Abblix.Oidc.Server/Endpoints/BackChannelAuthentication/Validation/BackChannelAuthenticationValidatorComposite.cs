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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Represents a composite validator for backchannel authentication contexts, aggregating multiple
/// validation steps into a single validation process.
/// This class implements <see cref="IBackChannelAuthenticationContextValidator"/>
/// and allows for the combination of multiple validators that are executed sequentially.
/// </summary>
/// <param name="validators">An array of validators that define the validation process.</param>
public class BackChannelAuthenticationValidatorComposite(IBackChannelAuthenticationContextValidator[] validators) : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Asynchronously validates a <see cref="BackChannelAuthenticationValidationContext"/>.
    /// Iterates through each validation step, returning the first encountered error, if any.
    /// </summary>
    /// <param name="context">The backchannel authentication validation context to be validated.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation.
    /// The task result contains a <see cref="OidcError"/>
    /// if a validation error is found, or null if validation succeeds.
    /// </returns>
    public async Task<OidcError?> ValidateAsync(
        BackChannelAuthenticationValidationContext context)
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
