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

using Abblix.Oidc.Client.AspNetCore;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.UnitTests.AspNetCore;

/// <summary>
/// The distributed-cache store, over a real in-memory <see cref="IDistributedCache"/> and the real cookie
/// machinery: a login stored on one response's cache-and-cookie, then read on the next request.
/// </summary>
/// <remarks>
/// The cache is shared across the store instances, standing in for the host's registered one; the cookie
/// is carried from response to request the way a browser would. The two together are the test's whole
/// point - the cache holds the context, the cookie holds the only key to it, and neither alone lets a
/// callback through.
/// </remarks>
public class DistributedCacheAuthorizationStateStoreTests
{
    private readonly IDistributedCache _cache = new MemoryDistributedCache(
        Options.Create(new MemoryDistributedCacheOptions()));

    private static AuthorizationContext ContextFor(string state) => new()
    {
        State = state,
        Nonce = "the-nonce",
        CodeVerifier = "the-verifier",
        ReturnUri = "/orders",
        Issuer = "https://provider.example.com",
        RedirectUri = "https://client.example.com/signin-oidc",
    };

    private DistributedCacheAuthorizationStateStore StoreFor(HttpContext httpContext)
    {
        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        return new DistributedCacheAuthorizationStateStore(
            accessor, _cache, Options.Create(new AuthorizationStateOptions()));
    }

    private static DefaultHttpContext NextRequestCarrying(HttpContext previousResponse)
    {
        var next = new DefaultHttpContext();

        var cookies = SetCookieHeaderValue.ParseList(previousResponse.Response.Headers.SetCookie)
            .Where(cookie => !string.IsNullOrEmpty(cookie.Value.Value))
            .Select(cookie => $"{cookie.Name}={cookie.Value}");

        var header = string.Join("; ", cookies);
        if (header.Length > 0)
            next.Request.Headers.Cookie = header;

        return next;
    }

    /// <summary>
    /// A login stored on the redirect comes back whole on the callback: the cache held it, the cookie
    /// found it.
    /// </summary>
    [Fact]
    public async Task StoresInTheCache_AndFindsByTheCookieKey()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var found = await StoreFor(callback).FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.NotNull(found);
        Assert.Equal("the-verifier", found.CodeVerifier);
    }

    /// <summary>
    /// The cookie carries a key, not the context: the verifier is in the cache, never in the cookie.
    /// </summary>
    [Fact]
    public async Task WritesOnlyAKeyToTheCookie()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var cookie = Assert.Single(SetCookieHeaderValue.ParseList(redirect.Response.Headers.SetCookie));

        Assert.True(cookie.HttpOnly);
        Assert.True(cookie.Secure);
        Assert.DoesNotContain("the-verifier", cookie.Value.Value);
    }

    /// <summary>
    /// The context in the cache is the binding's whole point: it is reachable only through the cookie key,
    /// so a callback without the cookie finds nothing even though the cache still holds the entry.
    /// </summary>
    [Fact]
    public async Task WithoutTheCookie_TheCachedEntryIsUnreachable()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        // A callback that carries the right state but not the cookie - an attacker who read the state from
        // the request URL but never held the victim's browser.
        var found = await StoreFor(new DefaultHttpContext())
            .FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Null(found);
    }

    /// <summary>
    /// A cookie key that points at no cache entry is a miss - an expired login, or one from a cache that
    /// has since dropped it.
    /// </summary>
    [Fact]
    public async Task ACookieKeyWithNoCacheEntry_IsAMiss()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        // The cache lost the entry (eviction, expiry) but the browser still has the cookie.
        var name = callback.Request.Cookies.Single().Key;
        var strayKey = callback.Request.Cookies[name]!;
        await _cache.RemoveAsync("abblix:oidc:client:authorization-state:" + strayKey, TestContext.Current.CancellationToken);

        var found = await StoreFor(callback).FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Null(found);
    }

    /// <summary>
    /// Removing reports whether the request carried the cookie, drops the cache entry, and deletes the
    /// cookie so a replay arrives keyless.
    /// </summary>
    [Fact]
    public async Task RemoveClearsTheCacheAndTheCookie()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var removed = await StoreFor(callback).RemoveAsync("the-state", TestContext.Current.CancellationToken);

        Assert.True(removed);

        // The entry is gone: a fresh callback carrying the same (now stale) cookie finds nothing.
        var replay = NextRequestCarrying(redirect);
        Assert.Null(await StoreFor(replay).FindAsync("the-state", TestContext.Current.CancellationToken));

        var deletion = Assert.Single(SetCookieHeaderValue.ParseList(callback.Response.Headers.SetCookie));
        Assert.Contains("the-state", deletion.Name.Value);
    }

    /// <summary>
    /// Removing without the cookie reports false - the replay a second callback would be.
    /// </summary>
    [Fact]
    public async Task RemoveReportsFalseWithoutTheCookie()
    {
        var removed = await StoreFor(new DefaultHttpContext())
            .RemoveAsync("the-state", TestContext.Current.CancellationToken);

        Assert.False(removed);
    }

    /// <summary>
    /// Two logins started at once keep separate cookies and separate cache entries, so neither overwrites
    /// the other.
    /// </summary>
    [Fact]
    public async Task ConcurrentLoginsDoNotCollide()
    {
        var redirect = new DefaultHttpContext();
        var store = StoreFor(redirect);
        await store.StoreAsync(ContextFor("state-one"), TestContext.Current.CancellationToken);
        await store.StoreAsync(ContextFor("state-two"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var find = StoreFor(callback);

        Assert.Equal("state-one", (await find.FindAsync("state-one", TestContext.Current.CancellationToken))?.State);
        Assert.Equal("state-two", (await find.FindAsync("state-two", TestContext.Current.CancellationToken))?.State);
    }

    /// <summary>
    /// Outside any request there is no cookie to read, and the store says so loudly.
    /// </summary>
    [Fact]
    public async Task ThrowsWhenThereIsNoRequestInFlight()
    {
        var store = new DistributedCacheAuthorizationStateStore(
            new HttpContextAccessor { HttpContext = null },
            _cache,
            Options.Create(new AuthorizationStateOptions()));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.FindAsync("the-state", TestContext.Current.CancellationToken));
    }
}
