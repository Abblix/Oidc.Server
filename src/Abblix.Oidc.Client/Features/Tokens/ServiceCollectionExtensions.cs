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


using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Registers the talker to the token endpoint.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the service that redeems grants at the provider's token endpoint.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configureOptions">A delegate that configures <see cref="TokenRequestOptions"/>.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddTokenRequests(
        this IServiceCollection services, Action<TokenRequestOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddHttpClient(TokenRequestService.HttpClientName);
        services.TryAddSingleton<ITokenRequestService, TokenRequestService>();

        return services;
    }
}
