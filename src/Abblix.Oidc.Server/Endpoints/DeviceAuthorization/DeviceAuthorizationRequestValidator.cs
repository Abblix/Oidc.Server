// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
