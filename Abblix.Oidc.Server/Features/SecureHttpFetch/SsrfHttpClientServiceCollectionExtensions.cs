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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Registers HTTP clients that initiate requests to client-supplied URLs (CIBA notification
/// endpoints, back-channel logout URIs, JWKS/issuer fetches). Every such client must route through
/// <see cref="SsrfValidatingHttpMessageHandler"/>; bundling the handler with the client registration
/// makes it impossible to add a new outbound client that silently skips SSRF protection.
/// </summary>
public static class SsrfHttpClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers a typed HTTP client whose primary handler is the SSRF-validating handler.
    /// </summary>
    public static IHttpClientBuilder AddSsrfHttpClient<TClient, TImplementation>(
        this IServiceCollection services,
        Action<IServiceProvider, HttpClient> configureClient)
        where TClient : class
        where TImplementation : class, TClient
        => services
            .AddHttpClient<TClient, TImplementation>(configureClient)
            .ConfigurePrimaryHttpMessageHandler<SsrfValidatingHttpMessageHandler>();

    /// <summary>
    /// Registers a named HTTP client whose primary handler is the SSRF-validating handler.
    /// </summary>
    public static IHttpClientBuilder AddSsrfHttpClient(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, HttpClient> configureClient)
        => services
            .AddHttpClient(name, configureClient)
            .ConfigurePrimaryHttpMessageHandler<SsrfValidatingHttpMessageHandler>();
}
