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

using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Registers the ASP.NET Core pieces of the client.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Replaces the in-memory authorization state store with the cookie-backed one, binding each login
    /// to the browser that started it.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// A plain <c>Add</c>, not a <c>TryAdd</c>, and on purpose: the in-memory store is what a host would
    /// otherwise resolve, and leaving it in place would defeat the reason to call this. Registering the
    /// cookie store as the last <see cref="IAuthorizationStateStore"/> makes it the one resolved, whether
    /// or not <c>AddAuthorizationRequests</c> or <c>AddAuthorizationStateConsumption</c> ran first.
    /// The dependencies it needs are requested here so a host does not have to know them:
    /// <c>AddHttpContextAccessor</c> for the request in flight, and Data Protection for the cookie
    /// payload - both are no-ops when the host has already added them.
    /// </remarks>
    public static IServiceCollection AddCookieAuthorizationStateStore(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddDataProtection();

        // Options must exist even when no host configured them, so the store can read the lifetime that
        // bounds the cookie; TryAdd-style AddOptions is safe whether or not the state feature ran.
        services.AddOptions<AuthorizationStateOptions>();

        // Registering an ASP.NET store IS the host saying it is server-side, so the response mode it
        // implies comes with it rather than waiting for a separate call the host has no reason to know
        // about. See AddServerSideResponseMode.
        services.AddServerSideResponseMode();

        // The last registration wins the singular resolve, so this deliberately overrides any in-memory
        // default a state-feature call left behind. TryAddEnumerable is not what is wanted here.
        services.RemoveAll<IAuthorizationStateStore>();
        services.AddSingleton<IAuthorizationStateStore, CookieAuthorizationStateStore>();

        return services;
    }

    /// <summary>
    /// Replaces the in-memory authorization state store with one that keeps each login in the host's
    /// distributed cache, with a secret key to it bound to the browser by a cookie.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// The choice between this and <see cref="AddCookieAuthorizationStateStore"/> is the host's, made by
    /// which one it calls: the cookie store carries the whole context in the cookie and needs nothing
    /// server-side, this one keeps the context in a cache and is the fit for a host already storing its
    /// post-login ticket the same way.
    /// It does NOT register a cache. The host must register an <see cref="IDistributedCache"/> - a memory
    /// one for a single node, a Redis one for several - and if it forgets, resolving the store fails at
    /// startup, which is the right signal. A default in-process cache here would instead let a
    /// multi-replica host run on a store that silently loses logins landing on another node.
    /// The other dependencies are requested for the host: <c>AddHttpContextAccessor</c> for the request
    /// in flight, both no-ops when already present.
    /// </remarks>
    public static IServiceCollection AddDistributedCacheAuthorizationStateStore(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddOptions<AuthorizationStateOptions>();
        services.AddServerSideResponseMode();

        // The last registration wins the singular resolve, overriding any in-memory default. The cache
        // itself is deliberately not registered - see the remarks: it is the host's to choose.
        services.RemoveAll<IAuthorizationStateStore>();
        services.AddSingleton<IAuthorizationStateStore, DistributedCacheAuthorizationStateStore>();

        return services;
    }

    /// <summary>
    /// Answers the response-mode question on behalf of a server-side host: a flow that returns tokens
    /// gets <c>form_post</c> unless the host named a mode itself.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// The base package refuses to guess this, because both plausible answers are wrong for somebody: the
    /// specification's default is the fragment, which by RFC 3986 section 3.5 "is dereferenced solely by
    /// the user agent" and so never reaches a server, while <c>form_post</c> is useless to a browser-based
    /// client that reads the fragment itself. Being ASP.NET, this host IS the server-side case, so here
    /// the answer is known and the refusal would be pedantry.
    /// It runs as a post-configure so it sees whatever the host set and leaves an explicit choice alone -
    /// filling a gap, never overriding an answer. <c>form_post</c> makes the provider return an HTML page
    /// that POSTs the parameters to the redirect address, which the callback reader already handles by
    /// reading the form when the request carries one.
    /// One thing this cannot do for the host: that POST arrives cross-site, from the provider's page, so
    /// it carries no ASP.NET antiforgery token. A callback endpoint with antiforgery validation on will
    /// reject it. The endpoint must opt out - <c>DisableAntiforgery()</c> on a minimal API route, or
    /// <c>[IgnoreAntiforgeryToken]</c> on an action - which is safe because this endpoint's CSRF defence
    /// is the <c>state</c> parameter (RFC 6749 section 10.12), checked by finding and then spending the
    /// stored login. An antiforgery token here would be a second, incompatible mechanism rather than an
    /// additional protection.
    /// </remarks>
    public static IServiceCollection AddServerSideResponseMode(this IServiceCollection services)
    {
        services.PostConfigure<AuthorizationRequestOptions>(options =>
        {
            if (options.Flow.ReturnsFrontChannelTokens() && string.IsNullOrEmpty(options.ResponseMode))
                options.ResponseMode = ResponseModes.FormPost;
        });

        return services;
    }
}
