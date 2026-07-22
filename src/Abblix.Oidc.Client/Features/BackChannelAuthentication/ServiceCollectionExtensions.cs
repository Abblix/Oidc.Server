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

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// Registers the CIBA grant.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the service that asks a provider to authenticate a person on a device this client cannot see.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Serves the poll delivery mode. Ping and push need the provider to call the application back, which is
    /// an endpoint of its own and is not part of this registration.
    /// </remarks>
    public static IServiceCollection AddBackChannelAuthentication(this IServiceCollection services)
    {
        services.AddHttpClient(BackChannelAuthenticationService.HttpClientName);

        // A soft default, so a test or a host can substitute a clock before this call. The clock is what the
        // polling waits on, so a test that could not replace it would have to sit through the intervals.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IBackChannelAuthenticationService, BackChannelAuthenticationService>();

        return services;
    }
}
