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
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Registers the presentation of access tokens to protected resources.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds what a host needs to present this client's access token to the APIs it calls.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// This registers no token source. A host that wires a resource client and never says where tokens come
    /// from gets a named refusal at the first call rather than an unauthenticated request, which the API
    /// answers 401 and everyone debugs as a token problem.
    /// </remarks>
    public static IServiceCollection AddProtectedResourceAccess(this IServiceCollection services)
    {
        services.TryAddSingleton<IAccessTokenSource, NoAccessTokenSource>();

        return services;
    }

    /// <summary>
    /// Says where access tokens come from.
    /// </summary>
    /// <typeparam name="TSource">The host's own source.</typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Registered as a singleton with no lifetime to choose, because the only other answers are wrong. A
    /// message handler outlives the request that triggered it, so a scoped source resolved inside one is a
    /// different instance from the one the request is using, and a source that remembered a user would hand
    /// that user's token to whoever calls next. Ambient state is read per call - through
    /// <c>IHttpContextAccessor</c>, which flows without a scope - not held in a field.
    /// Replaces rather than adds, so the answer does not depend on whether this ran before or after
    /// <see cref="AddProtectedResourceAccess"/>.
    /// </remarks>
    public static IServiceCollection AddAccessTokenSource<TSource>(this IServiceCollection services)
        where TSource : class, IAccessTokenSource
    {
        services.Replace(ServiceDescriptor.Singleton<IAccessTokenSource, TSource>());

        return services;
    }

    /// <summary>
    /// Presents this client's access token on the calls an <see cref="HttpClient"/> makes.
    /// </summary>
    /// <param name="builder">The client builder the host created for its resource.</param>
    /// <param name="configureOptions">Names the resource and the scopes it needs.</param>
    /// <returns>The same builder, so calls chain.</returns>
    /// <remarks>
    /// An extension on the host's own client rather than a client this library creates. Every named client
    /// this package registers carries traffic the client initiates toward the provider; a resource call is
    /// traffic the host initiates toward its own API, and owning its name, base address and handler chain
    /// would mean a host with its own typed client having to undo all of it.
    /// </remarks>
    public static IHttpClientBuilder AddAccessToken(
        this IHttpClientBuilder builder, Action<ProtectedResourceOptions> configureOptions)
    {
        builder.Services.Configure(builder.Name, configureOptions);
        builder.Services.AddProtectedResourceAccess();

        // Captured now, so the lifetime check below can actually read the registrations. Asking the built
        // provider for its own IServiceCollection returns nothing - nobody registers it - which would make
        // that check one that can never fire.
        var services = builder.Services;

        HardenPrimaryHandler(builder);

        builder.AddHttpMessageHandler(serviceProvider =>
        {
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<ProtectedResourceOptions>>()
                .Get(builder.Name);

            RequireUsableResource(builder.Name, options);
            RequireSingletonSource(services);

            return new AccessTokenHandler(
                serviceProvider.GetRequiredService<ILogger<AccessTokenHandler>>(),
                serviceProvider.GetRequiredService<IAccessTokenSource>(),
                options);
        });

        return builder;
    }

    /// <summary>
    /// Turns off two defaults that would leak or lose the credential.
    /// </summary>
    /// <remarks>
    /// Both are ours rather than a specification's, and both close a named failure. Automatic redirects mean
    /// the runtime follows a 3xx and strips the Authorization header as it goes - correct, and never to be
    /// undone - so what arrives is an anonymous request whose 401 reads as an expiry. A shared cookie
    /// container means an ambient session cookie rides along to the resource server beside the bearer token.
    /// The primary handler is mutated rather than replaced. Every design that reaches for
    /// <c>ConfigurePrimaryHttpMessageHandler</c> throws away whatever the host configured on that handler -
    /// a client certificate, a proxy, connection pooling - or is thrown away by it, depending on which ran
    /// last.
    /// </remarks>
    private static void HardenPrimaryHandler(IHttpClientBuilder builder)
        => builder.Services.Configure<HttpClientFactoryOptions>(
            builder.Name,
            options => options.HttpMessageHandlerBuilderActions.Add(handlerBuilder =>
            {
                switch (handlerBuilder.PrimaryHandler)
                {
                    case SocketsHttpHandler sockets:
                        sockets.AllowAutoRedirect = false;
                        sockets.UseCookies = false;
                        break;

                    case HttpClientHandler client:
                        client.AllowAutoRedirect = false;
                        client.UseCookies = false;
                        break;

                    default:
                        // A primary handler of some other kind is left alone rather than replaced. The
                        // handler's own comparison of where the request ended up is the backstop.
                        break;
                }
            }));

    /// <summary>
    /// Refuses a resource address a token could not safely be scoped to.
    /// </summary>
    /// <remarks>
    /// Checked when the client is first built rather than at the first call, so a mistake surfaces where it
    /// was made. The fragment is refused because RFC 8707 section 2 says a resource indicator "MUST NOT
    /// include a fragment component"; the query is ours, because a query cannot act as a path prefix and a
    /// resource carrying one would authorize more than it appears to.
    /// </remarks>
    private static void RequireUsableResource(string name, ProtectedResourceOptions options)
    {
        if (options.Resource is not { } resource)
        {
            throw new AccessTokenPresentationException(
                $"The HTTP client '{name}' presents an access token but names no resource. Set "
                + $"{nameof(ProtectedResourceOptions)}.{nameof(ProtectedResourceOptions.Resource)}.");
        }

        if (!resource.IsAbsoluteUri
            || !string.Equals(resource.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(resource.Fragment)
            || !string.IsNullOrEmpty(resource.Query))
        {
            throw new AccessTokenPresentationException(
                $"The resource '{resource}' of HTTP client '{name}' must be an absolute https address with "
                + "no query and no fragment (RFC 8707 section 2).");
        }
    }

    /// <summary>
    /// Refuses a token source registered with a lifetime that would hand one user's token to another.
    /// </summary>
    /// <remarks>
    /// The one defect no container validation catches. A scoped source resolves perfectly legally inside the
    /// handler's own scope, so <c>ValidateScopes</c> and <c>ValidateOnBuild</c> both stay silent - and the
    /// instance the handler captured then serves every user for the two minutes the handler is pooled.
    /// Checked at first handler construction rather than at registration, so it sees sources registered
    /// after this call.
    /// </remarks>
    private static void RequireSingletonSource(IServiceCollection services)
    {
        var descriptor = services.LastOrDefault(
            service => service.ServiceType == typeof(IAccessTokenSource));

        if (descriptor is not null && descriptor.Lifetime != ServiceLifetime.Singleton)
        {
            throw new AccessTokenPresentationException(
                $"{nameof(IAccessTokenSource)} is registered as {descriptor.Lifetime}, and a message handler "
                + "outlives the request that triggered it. The instance captured here would serve every "
                + "later caller, so one user's token would be presented for another. Register it as a "
                + "singleton and read per-request state through IHttpContextAccessor.");
        }
    }
}
