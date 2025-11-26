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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the Device Code grant type as defined in RFC 8628.
/// This handler validates token requests for the device authorization flow,
/// checking the device code status and returning tokens when authorized.
/// </summary>
/// <param name="storage">Service for storing and retrieving device authorization requests.</param>
/// <param name="parameterValidator">Service to validate request parameters.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options containing polling interval settings.</param>
public class DeviceCodeGrantHandler(
    IDeviceAuthorizationStorage storage,
    IParameterValidator parameterValidator,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options) : IAuthorizationGrantHandler
{
    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.DeviceAuthorization; }
    }

    /// <inheritdoc />
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
        TokenRequest request,
        ClientInfo clientInfo)
    {
        parameterValidator.Required(request.DeviceCode, nameof(request.DeviceCode));

        var deviceRequest = await storage.TryGetByDeviceCodeAsync(request.DeviceCode);

        var deviceAuthOptions = options.Value.DeviceAuthorization
            .NotNull(nameof(OidcOptions.DeviceAuthorization));
        var pollingInterval = deviceAuthOptions.PollingInterval;

        switch (deviceRequest)
        {
            // Device code not found or expired
            case null:
                return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired");

            // Device code belongs to different client
            case { ClientId: var clientId } when clientId != clientInfo.ClientId:
                return new OidcError(ErrorCodes.InvalidGrant, "The device code was issued to another client");

            // User has authorized the device - atomically claim the authorization
            case { Status: DeviceAuthorizationStatus.Authorized }
                when !await storage.TryRemoveAsync(request.DeviceCode, deviceRequest.UserCode):

                // Use atomic get-and-remove to prevent race conditions where two concurrent requests
                // could both retrieve the authorized grant. Per RFC 8628 Section 3.5, each device code
                // MUST only be exchanged for tokens once.

                return new OidcError(
                    ErrorCodes.ExpiredToken,
                    "The device code has expired or was already used");

            // User has authorized the device - return the authorized grant
            case { Status: DeviceAuthorizationStatus.Authorized, AuthorizedGrant: { } authorizedGrant }:
                return authorizedGrant;

            // Authorization still pending - check polling rate
            case { Status: DeviceAuthorizationStatus.Pending, NextPollAt: { } nextPollAt }
                when timeProvider.GetUtcNow() < nextPollAt:

                // Polling too fast - increase the interval per RFC 8628 Section 3.5
                deviceRequest.NextPollAt = nextPollAt + pollingInterval;
                await storage.UpdateAsync(request.DeviceCode, deviceRequest);

                return new OidcError(
                    ErrorCodes.SlowDown,
                    "Polling too frequently. Increase the interval between requests.");

            // Authorization still pending - update next poll time
            case { Status: DeviceAuthorizationStatus.Pending }:

                deviceRequest.NextPollAt = timeProvider.GetUtcNow() + pollingInterval;
                await storage.UpdateAsync(request.DeviceCode, deviceRequest);

                return new OidcError(
                    ErrorCodes.AuthorizationPending,
                    "The authorization request is still pending. The user has not yet completed authorization.");

            // User denied the request
            case { Status: DeviceAuthorizationStatus.Denied }:
                await storage.RemoveAsync(request.DeviceCode);
                return new OidcError(
                    ErrorCodes.AccessDenied,
                    "The user denied the authorization request.");

            default:
                throw new InvalidOperationException(
                    $"Unexpected device authorization status: {deviceRequest.Status}");
        }
    }
}
