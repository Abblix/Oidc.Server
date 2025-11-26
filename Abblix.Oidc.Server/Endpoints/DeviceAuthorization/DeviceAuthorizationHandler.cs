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
