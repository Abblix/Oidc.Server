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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.DeviceAuthorization;

/// <summary>
/// Registers the device authorization grant.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the service that signs in a device with no browser of its own, per RFC 8628.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Needs <c>AddTokenRequests</c>, which redeems the device code, and a client authentication method the
    /// provider accepts at both endpoints.
    /// </remarks>
    public static IServiceCollection AddDeviceAuthorization(this IServiceCollection services)
    {
        services.AddHttpClient(DeviceAuthorizationService.HttpClientName);

        // A soft default, so a test or a host can substitute a clock before this call. The clock is what the
        // polling waits on, so a test that could not replace it would have to sit through the intervals.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IDeviceAuthorizationService, DeviceAuthorizationService>();

        return services;
    }
}
