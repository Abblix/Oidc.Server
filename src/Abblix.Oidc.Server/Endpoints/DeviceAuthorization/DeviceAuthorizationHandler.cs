// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Handles device authorization requests as defined in RFC 8628.
/// Coordinates validation and processing of requests to generate device_code and user_code.
/// </summary>
/// <param name="validator">The service responsible for validating device authorization requests.</param>
/// <param name="processor">The service responsible for processing validated requests.</param>
public class DeviceAuthorizationHandler(
    IDeviceAuthorizationRequestValidator validator,
    IDeviceAuthorizationRequestProcessor processor) : IDeviceAuthorizationHandler
{
    /// <inheritdoc />
    public async Task<Result<DeviceAuthorizationResponse, OidcError>> HandleAsync(
        DeviceAuthorizationRequest request,
        ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(request, clientRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
