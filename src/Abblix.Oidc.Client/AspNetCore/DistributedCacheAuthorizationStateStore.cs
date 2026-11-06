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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Keeps each pending login in a distributed cache the host supplies, with only a secret key to it held
/// in a cookie on the browser that started it.
/// </summary>
/// <remarks>
/// The counterpart to the cookie store, for when the context should not ride in the cookie itself - the
/// same choice the post-login ticket faces, so a host that already stores that in a distributed cache
/// keeps one mechanism. The cookie here carries nothing but a random session key; the context, code
/// verifier and all, lives in the cache under that key. The binding is unchanged: the session key is
/// unguessable, <c>HttpOnly</c>, same-origin, so an attacker who knows the (non-secret) <c>state</c>
/// value cannot reach the entry without the cookie the victim's browser holds.
/// The cache is the HOST's to provide and this class only consumes <see cref="IDistributedCache"/>. It
/// deliberately does not register one: a library that defaulted to an in-process cache would hand a
/// multi-replica host a store that silently fails whenever a callback lands on another node, masking the
/// misconfiguration instead of letting the missing registration fail loud. The host wires
/// <c>AddDistributedMemoryCache</c> for one node, a Redis cache for several, or its own store entirely.
/// The cache value is stored as plain JSON, since the cache is server-side infrastructure the value
/// never leaves; the secret that gates access is the session key in the cookie.
/// </remarks>
/// <param name="httpContextAccessor">Reaches the request being handled, whose cookies this reads and writes.</param>
/// <param name="cache">The distributed cache the host registered; this class never registers one itself.</param>
/// <param name="options">Carries the lifetime that bounds both the cookie and the cache entry.</param>
internal sealed class DistributedCacheAuthorizationStateStore(
    IHttpContextAccessor httpContextAccessor,
    IDistributedCache cache,
    IOptions<AuthorizationStateOptions> options) : IAuthorizationStateStore
{
    // Names the cookie for its login's state value, so several logins started at once (a user with two
    // tabs) keep separate cookies. The cookie's VALUE is the secret; its name, which encodes the
    // non-secret state, only picks which cookie to read.
    private const string CookieNamePrefix = ".Abblix.Oidc.Client.AuthorizationSession.";

    // Namespaces the cache key so the session key cannot collide with anything else the host keeps in the
    // same cache.
    private const string CacheKeyPrefix = "abblix:oidc:client:authorization-state:";

    private const int SessionKeyByteCount = 32;

    public async Task StoreAsync(AuthorizationContext context, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        var sessionKey = NewSessionKey();

        await cache.SetStringAsync(
            CacheKey(sessionKey),
            JsonSerializer.Serialize(context),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = options.Value.Lifetime },
            cancellationToken);

        httpContext.Response.Cookies.Append(CookieName(context.State), sessionKey, CookieOptions());
    }

    public async Task<AuthorizationContext?> FindAsync(string state, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        if (!httpContext.Request.Cookies.TryGetValue(CookieName(state), out var sessionKey)
            || string.IsNullOrEmpty(sessionKey))
        {
            return null;
        }

        var payload = await cache.GetStringAsync(CacheKey(sessionKey), cancellationToken);
        if (payload is null)
            return null;

        var context = Deserialize(payload);

        // The cookie's name encodes the state it was stored under; a callback whose state does not match
        // the context in the entry the cookie points to is not this login, so it is a miss. This guards a
        // cookie whose name and content were made to disagree.
        return context is not null && string.Equals(context.State, state, StringComparison.Ordinal)
            ? context
            : null;
    }

    public async Task<bool> RemoveAsync(string state, CancellationToken cancellationToken = default)
    {
        var httpContext = RequireHttpContext();

        // The key is tested where it is used rather than collapsed into a presence flag first. A flag
        // carries the answer without carrying what proved it, so the use below would need an assertion by
        // hand; kept together, the compiler proves it, and a later edit that moves the test cannot leave a
        // stale one behind. An empty cookie counts as absent, the same reading FindAsync gives it.
        if (httpContext.Request.Cookies.TryGetValue(CookieName(state), out var sessionKey)
            && !string.IsNullOrEmpty(sessionKey))
        {
            await cache.RemoveAsync(CacheKey(sessionKey), cancellationToken);
        }

        // The deletion cookie makes the browser drop the session key, so a replayed callback arrives
        // without it and finds nothing - the single-use spend, carried by the same cookie the binding is.
        httpContext.Response.Cookies.Delete(CookieName(state), CookieOptions());

        // A callback that arrived without the key held no login to spend, which is the false a replay gets.
        return !string.IsNullOrEmpty(sessionKey);
    }

    private static AuthorizationContext? Deserialize(string payload)
    {
        // A cache holding a value this cannot read is a miss, not a fault - the same answer as no entry.
        try
        {
            return JsonSerializer.Deserialize<AuthorizationContext>(payload);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private HttpContext RequireHttpContext() =>
        httpContextAccessor.HttpContext
        ?? throw new InvalidOperationException(
            "The distributed-cache authorization state store needs an HTTP request in flight, and none is "
            + "current. It runs during the redirect to the provider and the callback back; a caller "
            + "outside a request should use the in-memory store instead.");

    private static string NewSessionKey() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(SessionKeyByteCount));

    private static string CookieName(string state) => CookieNamePrefix + state;

    private static string CacheKey(string sessionKey) => CacheKeyPrefix + sessionKey;

    private CookieOptions CookieOptions() => new()
    {
        // The cookie carries the session key, which is the only thing standing between an attacker and the
        // cached context; keeping script out of it is the point of HttpOnly.
        HttpOnly = true,

        // Only over TLS (RFC 9700 section 2.6).
        Secure = true,

        // Lax carries the cookie on the provider's top-level GET redirect back to the callback without
        // sending it on the cross-site subrequests None would allow; this client uses no form_post mode
        // that would need None.
        SameSite = SameSiteMode.Lax,

        MaxAge = options.Value.Lifetime,
        Path = "/",
    };
}
