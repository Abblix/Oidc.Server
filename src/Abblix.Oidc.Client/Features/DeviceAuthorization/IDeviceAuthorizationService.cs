// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.DeviceAuthorization;

/// <summary>
/// Signs in a device that cannot show a browser, per RFC 8628.
/// </summary>
public interface IDeviceAuthorizationService
{
    /// <summary>
    /// Asks the provider for a code pair: one the device shows its user, one it keeps.
    /// </summary>
    /// <param name="scopes">What the eventual tokens are to be good for. Optional, per section 3.1.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="DeviceAuthorizationException">
    /// The provider refused, could not be reached, or publishes no device authorization endpoint.
    /// </exception>
    Task<DeviceAuthorizationResponse> RequestAsync(
        IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Polls the token endpoint until the user has authorized the device, refused it, or the exchange has
    /// expired.
    /// </summary>
    /// <param name="authorization">What <see cref="RequestAsync"/> returned.</param>
    /// <param name="cancellationToken">Stops the polling.</param>
    /// <returns>The tokens, once the user has authorized the device.</returns>
    /// <exception cref="TokenRequestException">
    /// The exchange ended without tokens: the user refused it, the code expired, or the provider raised an
    /// error that RFC 8628 section 3.5 does not have a client poll through.
    /// </exception>
    /// <remarks>
    /// The waiting is the substance of this method rather than an implementation detail. Section 3.5 tells a
    /// client to wait the interval before each attempt and to add five seconds every time the provider
    /// answers <c>slow_down</c>; a loop that ignores either turns the device into a denial of service
    /// against the provider, and gets itself throttled or blocked for the trouble.
    /// </remarks>
    Task<TokenResponse> WaitForTokensAsync(
        DeviceAuthorizationResponse authorization, CancellationToken cancellationToken = default);
}
