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
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Validates device authorization requests by delegating to a context validator.
/// </summary>
/// <param name="contextValidator">The validator for performing detailed validation.</param>
public class DeviceAuthorizationRequestValidator(
    IDeviceAuthorizationContextValidator contextValidator) : IDeviceAuthorizationRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidDeviceAuthorizationRequest, OidcError>> ValidateAsync(
        DeviceAuthorizationRequest request,
        ClientRequest clientRequest)
    {
        var context = new DeviceAuthorizationValidationContext(request, clientRequest);

        var error = await contextValidator.ValidateAsync(context);
        if (error != null)
            return error;

        return new ValidDeviceAuthorizationRequest(context);
    }
}
