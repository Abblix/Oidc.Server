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
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options containing polling interval settings.</param>
public class DeviceCodeGrantHandler(
    IDeviceAuthorizationStorage storage,
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
        ClientInfo clientInfo,
    CancellationToken cancellationToken)
    {
        // RFC 6749 §5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.DeviceCode.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.DeviceCode);
        }

        var deviceRequest = await storage.TryGetByDeviceCodeAsync(request.DeviceCode);

        var deviceAuthOptions = options.Value.DeviceAuthorization
            .NotNull(nameof(OidcOptions.DeviceAuthorization));
        var pollingInterval = deviceAuthOptions.PollingInterval;

        // A single clock read shared by the expiry gate and the remaining-lifetime passed to UpdateAsync, so
        // the two never disagree and the refreshed cache TTL is guaranteed positive (RFC 8628 §3.2).
        var now = timeProvider.GetUtcNow();

        switch (deviceRequest)
        {
            // Device code not found or expired
            case null:
                return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired");

            // Device code belongs to different client
            case { ClientId: var clientId } when clientId != clientInfo.ClientId:
                return new OidcError(ErrorCodes.InvalidGrant, "The device code was issued to another client");

            // Code has reached its fixed RFC 8628 §3.2 lifetime - reject and clean up rather than letting a
            // polling client keep it alive by resetting the cache TTL
            case { } when now >= deviceRequest.ExpiresAt:
                await storage.RemoveAsync(request.DeviceCode);
                return new OidcError(ErrorCodes.ExpiredToken, "The device code has expired");

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
                when now < nextPollAt:

                // Polling too fast - increase the interval per RFC 8628 Section 3.5. Persisting the stale
                // Pending snapshot here would revert an approval that landed after the read above, so the
                // helper re-reads and this re-dispatches when the status has advanced under us.
                if (!await TryBumpNextPollAsync(
                        request.DeviceCode, nextPollAt + pollingInterval, deviceRequest.ExpiresAt - now))
                {
                    return await AuthorizeAsync(request, clientInfo, cancellationToken);
                }

                return new OidcError(
                    ErrorCodes.SlowDown,
                    "Polling too frequently. Increase the interval between requests.");

            // Authorization still pending - update next poll time
            case { Status: DeviceAuthorizationStatus.Pending }:

                if (!await TryBumpNextPollAsync(
                        request.DeviceCode, now + pollingInterval, deviceRequest.ExpiresAt - now))
                {
                    return await AuthorizeAsync(request, clientInfo, cancellationToken);
                }

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

    // Re-reads the record and only writes the rate-limit bump when it is still Pending, so a concurrent
    // approval is not overwritten. Returns false when the status has advanced, signalling the caller to
    // re-dispatch on the fresh state. The remaining lifetime is computed by the caller from the same clock
    // read as the expiry gate, so the refreshed cache TTL stays positive and cannot extend the code
    private async Task<bool> TryBumpNextPollAsync(string deviceCode, DateTimeOffset nextPollAt, TimeSpan remaining)
    {
        var current = await storage.TryGetByDeviceCodeAsync(deviceCode);
        if (current is not { Status: DeviceAuthorizationStatus.Pending })
        {
            return false;
        }

        current.NextPollAt = nextPollAt;
        await storage.UpdateAsync(deviceCode, current, remaining);
        return true;
    }
}
