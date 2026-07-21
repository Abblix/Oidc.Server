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


using Abblix.Oidc.Client.Features.SigningKeys;
using Abblix.Oidc.Client.Features.TokenValidation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.BackChannelLogout;

/// <summary>
/// Registers the validator of Logout Tokens the provider posts to this client.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the validator of back-channel logout notifications.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Registering this is the whole opt-in. A client that does not call it has no endpoint to post to, and
    /// nothing accepts a Logout Token by default.
    /// </remarks>
    public static IServiceCollection AddBackChannelLogout(this IServiceCollection services)
    {
        services.AddLogging();
        services.AddSigningKeys();
        services.AddProviderTokenValidation();
        services.TryAddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();

        return services;
    }
}
