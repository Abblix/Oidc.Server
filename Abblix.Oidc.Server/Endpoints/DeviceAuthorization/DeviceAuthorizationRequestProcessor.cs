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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using DeviceAuthorizationRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Processes validated device authorization requests, generating codes and storing the request.
/// </summary>
/// <param name="storage">Storage for persisting device authorization requests.</param>
/// <param name="deviceCodeGenerator">Generator for high-entropy device codes.</param>
/// <param name="userCodeGenerator">Generator for user-friendly verification codes.</param>
/// <param name="options">Configuration options for device authorization.</param>
/// <param name="timeProvider">Provider for current time.</param>
public class DeviceAuthorizationRequestProcessor(
    IDeviceAuthorizationStorage storage,
    IDeviceCodeGenerator deviceCodeGenerator,
    IUserCodeGenerator userCodeGenerator,
    IOptionsSnapshot<OidcOptions> options,
    TimeProvider timeProvider) : IDeviceAuthorizationRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<DeviceAuthorizationResponse, OidcError>> ProcessAsync(
        ValidDeviceAuthorizationRequest request)
    {
        request.ClientInfo.CheckClientLicense();

        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        var deviceCode = deviceCodeGenerator.GenerateDeviceCode();
        var userCode = userCodeGenerator.GenerateUserCode();

        var deviceRequest = new DeviceAuthorizationRequest(
            request.ClientInfo.ClientId,
            request.Scope,
            request.Resources,
            userCode)
        {
            Status = DeviceAuthorizationStatus.Pending,
            NextPollAt = timeProvider.GetUtcNow() + deviceAuthOptions.PollingInterval,
        };

        await storage.StoreAsync(deviceCode, deviceRequest, deviceAuthOptions.CodeLifetime);

        return new DeviceAuthorizationResponse
        {
            DeviceCode = deviceCode,
            UserCode = userCode,
            ExpiresIn = deviceAuthOptions.CodeLifetime,
            Interval = deviceAuthOptions.PollingInterval,
        };
    }
}
