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

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Composes multiple device authorization context validators into a single validator.
/// Executes validators in sequence until one returns an error or all pass.
/// </summary>
/// <param name="validators">The collection of validators to execute.</param>
public class DeviceAuthorizationValidatorComposite(
    IEnumerable<IDeviceAuthorizationContextValidator> validators) : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
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
