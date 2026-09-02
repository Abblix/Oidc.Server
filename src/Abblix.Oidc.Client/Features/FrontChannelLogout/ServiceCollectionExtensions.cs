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

namespace Abblix.Oidc.Client.Features.FrontChannelLogout;

/// <summary>
/// Registers the reader of front-channel logout requests.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the reader of the requests a provider renders in a frame to log this client out.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configureOptions">A delegate that configures <see cref="FrontChannelLogoutOptions"/>.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Registering this is the whole opt-in, and it is worth knowing what is being opted into: a
    /// front-channel logout carries no token and proves nothing. It is a hint to end a local session, and
    /// a host that wants a statement it can act on beyond that wants the back channel.
    /// </remarks>
    public static IServiceCollection AddFrontChannelLogout(
        this IServiceCollection services, Action<FrontChannelLogoutOptions>? configureOptions = null)
    {
        if (configureOptions is not null)
            services.Configure(configureOptions);

        services.AddOptions<FrontChannelLogoutOptions>();
        services.TryAddSingleton<IFrontChannelLogoutRequestReader, FrontChannelLogoutRequestReader>();

        return services;
    }
}
