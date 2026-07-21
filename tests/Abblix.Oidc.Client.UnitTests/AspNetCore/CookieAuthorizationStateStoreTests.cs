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
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.UnitTests.AspNetCore;

/// <summary>
/// The cookie-backed store, exercised through the real cookie machinery: a login stored on one request's
/// response, then carried as a cookie into the next request and read back.
/// </summary>
/// <remarks>
/// The round-trip is the point. A test that reached inside and compared protected bytes would prove the
/// store agrees with itself; carrying the cookie from a response to a request proves it agrees with the
/// browser, which is the only party that matters. One Data Protection provider is shared across the store
/// instances so the protector on the write side and the read side are the same, exactly as they are in a
/// process serving both the redirect and the callback.
/// </remarks>
public class CookieAuthorizationStateStoreTests
{
    private readonly IDataProtectionProvider _dataProtection = new EphemeralDataProtectionProvider();

    private static AuthorizationContext ContextFor(string state) => new()
    {
        State = state,
        Nonce = "the-nonce",
        CodeVerifier = "the-verifier",
        ReturnUri = "/orders",
        Issuer = "https://provider.example.com",
        RedirectUri = "https://client.example.com/signin-oidc",
    };

    private CookieAuthorizationStateStore StoreFor(HttpContext httpContext)
    {
        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        return new CookieAuthorizationStateStore(
            accessor, _dataProtection, Options.Create(new AuthorizationStateOptions()));
    }

    /// <summary>
    /// Carries every <c>Set-Cookie</c> a response wrote into the request cookies of the next context, the
    /// way a browser would present them on the callback.
    /// </summary>
    private static DefaultHttpContext NextRequestCarrying(HttpContext previousResponse)
    {
        var next = new DefaultHttpContext();

        var cookies = SetCookieHeaderValue.ParseList(previousResponse.Response.Headers.SetCookie)
            // A deletion is written as a cookie whose value is empty and whose expiry is in the past; a
            // browser drops it rather than sending it back, so the test does the same.
            .Where(cookie => !string.IsNullOrEmpty(cookie.Value.Value))
            .Select(cookie => $"{cookie.Name}={cookie.Value}");

        var header = string.Join("; ", cookies);
        if (header.Length > 0)
            next.Request.Headers.Cookie = header;

        return next;
    }

    /// <summary>
    /// A login stored on the redirect response comes back whole on the callback request.
    /// </summary>
    [Fact]
    public async Task StoresOnTheResponse_AndFindsOnTheNextRequest()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var found = await StoreFor(callback).FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.NotNull(found);
        Assert.Equal("the-verifier", found.CodeVerifier);
        Assert.Equal("https://provider.example.com", found.Issuer);
    }

    /// <summary>
    /// The cookie is written with the flags that make the binding worth anything: HttpOnly keeps script
    /// out, Secure keeps it off plaintext, and its value is not the context in the clear.
    /// </summary>
    [Fact]
    public async Task WritesAProtectedHttpOnlySecureCookie()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var cookie = Assert.Single(SetCookieHeaderValue.ParseList(redirect.Response.Headers.SetCookie));

        Assert.True(cookie.HttpOnly);
        Assert.True(cookie.Secure);
        Assert.Equal(Microsoft.Net.Http.Headers.SameSiteMode.Lax, cookie.SameSite);
        // The verifier must not be legible in the cookie value.
        Assert.DoesNotContain("the-verifier", cookie.Value.Value);
    }

    /// <summary>
    /// A callback carrying no cookie matches nothing - the ordinary "not my login" miss.
    /// </summary>
    [Fact]
    public async Task FindsNothingWithoutTheCookie()
    {
        var found = await StoreFor(new DefaultHttpContext())
            .FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Null(found);
    }

    /// <summary>
    /// A tampered cookie value is a miss, not a throw: it is a callback this login cannot own, the same
    /// answer as no cookie at all.
    /// </summary>
    [Fact]
    public async Task FindsNothingWhenTheCookieWasTampered()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var name = callback.Request.Cookies.Single().Key;
        // Flip the payload: Data Protection authenticates it, so unprotect fails and the store reports a miss.
        callback.Request.Headers.Cookie = $"{name}=tampered-value";

        var found = await StoreFor(callback).FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Null(found);
    }

    /// <summary>
    /// A cookie protected for another purpose does not decrypt here, so a value lifted from elsewhere in
    /// the application is a miss rather than a foothold.
    /// </summary>
    [Fact]
    public async Task FindsNothingWhenTheCookieWasProtectedForAnotherPurpose()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var name = callback.Request.Cookies.Single().Key;
        var foreign = _dataProtection.CreateProtector("some.other.purpose").Protect("{}");
        callback.Request.Headers.Cookie = $"{name}={foreign}";

        var found = await StoreFor(callback).FindAsync("the-state", TestContext.Current.CancellationToken);

        Assert.Null(found);
    }

    /// <summary>
    /// Removing reports whether the request actually carried the cookie, and writes the deletion that makes
    /// the browser drop it - the single-use spend in cookie terms.
    /// </summary>
    [Fact]
    public async Task RemoveReportsPresenceAndDeletesTheCookie()
    {
        var redirect = new DefaultHttpContext();
        await StoreFor(redirect).StoreAsync(ContextFor("the-state"), TestContext.Current.CancellationToken);

        var callback = NextRequestCarrying(redirect);
        var removed = await StoreFor(callback).RemoveAsync("the-state", TestContext.Current.CancellationToken);

        Assert.True(removed);
        // A deletion cookie of the same name goes out on the response, dated in the past so the browser drops it.
        var deletion = Assert.Single(SetCookieHeaderValue.ParseList(callback.Response.Headers.SetCookie));
        Assert.Contains("the-state", deletion.Name.Value);
        Assert.True(deletion.Expires < TimeProvider.System.GetUtcNow());
    }

    /// <summary>
    /// Removing a cookie the request never carried reports false - the replay a second callback would be.
    /// </summary>
    [Fact]
    public async Task RemoveReportsFalseWhenTheCookieWasNotPresent()
    {
        var removed = await StoreFor(new DefaultHttpContext())
            .RemoveAsync("the-state", TestContext.Current.CancellationToken);

        Assert.False(removed);
    }

    /// <summary>
    /// Outside any request there is no cookie jar to use, and the store says so loudly rather than
    /// silently doing nothing.
    /// </summary>
    [Fact]
    public async Task ThrowsWhenThereIsNoRequestInFlight()
    {
        var store = new CookieAuthorizationStateStore(
            new HttpContextAccessor { HttpContext = null },
            _dataProtection,
            Options.Create(new AuthorizationStateOptions()));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.FindAsync("the-state", TestContext.Current.CancellationToken));
    }
}
