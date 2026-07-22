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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.PasswordGrant;

/// <summary>
/// Registers the resource owner password credentials grant.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the service that trades an end-user's username and password for tokens.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Calling this is the deliberate act the grant deserves. RFC 9700 section 2.4 says it MUST NOT be used,
    /// and the reasons are worth reading before this line is written: see <see cref="IPasswordGrantService"/>.
    /// A host talking to a provider that supports anything else should use that instead - the authorization
    /// code flow for a person at a browser, the device grant for a person without one, CIBA for a person
    /// elsewhere, client credentials for no person at all.
    ///
    /// The name is spelled out rather than shortened, so that a search for it in a codebase finds every
    /// application that opted in.
    /// </remarks>
    public static IServiceCollection AddResourceOwnerPasswordCredentials(this IServiceCollection services)
    {
        // The same named client as the other token-endpoint grants: it is the same endpoint, and a host
        // tuning its transport should not have to discover a second name.
        services.AddHttpClient(TokenRequestService.HttpClientName);

        services.TryAddSingleton<IPasswordGrantService, PasswordGrantService>();

        return services;
    }
}
