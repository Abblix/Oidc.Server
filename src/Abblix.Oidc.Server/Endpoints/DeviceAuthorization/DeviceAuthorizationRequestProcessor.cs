// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

            // The device may poll from the moment it holds the code, so the first allowed poll is now.
            // RFC 8628 section 3.2 defines the interval as "the minimum amount of time in seconds that
            // the client SHOULD wait between polling requests to the token endpoint" - it bounds the gap
            // BETWEEN polls, and at issuance there is no earlier poll for it to sit after. This used to
            // read now + interval, which answered the device's very first request with slow_down: not a
            // violation, since slow_down is a variant of authorization_pending and a conforming device
            // simply waits, but it charged every sign-in one interval of latency for polling too fast
            // when nothing had been polled at all. The first poll stamps the interval, and the throttle
            // governs every request after it.
            NextPollAt = timeProvider.GetUtcNow(),

            // RFC 9396 §3: stash authorization_details on the persisted record so the
            // host's user-verification step can read it (via ValidUserCode) and thread it
            // onto the AuthorizedGrant's AuthorizationContext when approving.
            AuthorizationDetails = request.AuthorizationDetails,
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
