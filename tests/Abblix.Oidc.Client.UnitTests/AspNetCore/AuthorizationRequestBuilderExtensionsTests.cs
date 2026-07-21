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
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.UnitTests.AspNetCore;

/// <summary>
/// Starting a login from an endpoint: the redirect to the provider and the state cookie must leave on the
/// same response, so the browser is bound to the login before it is sent away.
/// </summary>
public class AuthorizationRequestBuilderExtensionsTests
{
    private const string Issuer = "https://provider.example.com";
    private const string AuthorizationEndpoint = $"{Issuer}/authorize";

    private readonly IDataProtectionProvider _dataProtection = new EphemeralDataProtectionProvider();

    // Executing an IResult resolves framework services (a logger, for one) from the request's service
    // provider, which a bare DefaultHttpContext does not have; a minimal one carries the redirect result.
    private static readonly IServiceProvider RequestServices =
        new ServiceCollection().AddLogging().BuildServiceProvider();

    private static DefaultHttpContext HttpContext() => new() { RequestServices = RequestServices };

    /// <summary>
    /// Builds the request against a cookie-backed store bound to <paramref name="httpContext"/>, so the
    /// challenge and the store write to the same response.
    /// </summary>
    private IAuthorizationRequestBuilder BuilderFor(HttpContext httpContext)
    {
        var metadataProvider = new ConfiguredMetadataProvider(new ProviderMetadata
        {
            Issuer = Issuer,
            AuthorizationEndpoint = AuthorizationEndpoint,
        });

        var store = new CookieAuthorizationStateStore(
            new HttpContextAccessor { HttpContext = httpContext },
            _dataProtection,
            Options.Create(new AuthorizationStateOptions()));

        return new AuthorizationRequestBuilder(
            metadataProvider,
            new PkceProvider(metadataProvider),
            store,
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(new AuthorizationRequestOptions
            {
                RedirectUri = new Uri("https://client.example.com/signin-oidc"),
            }));
    }

    /// <summary>
    /// The challenge is a 302 to the provider's authorization endpoint.
    /// </summary>
    [Fact]
    public async Task RedirectsToTheAuthorizationEndpoint()
    {
        var httpContext = HttpContext();

        var result = await BuilderFor(httpContext)
            .ChallengeAsync("/orders", TestContext.Current.CancellationToken);
        await result.ExecuteAsync(httpContext);

        Assert.Equal(StatusCodes.Status302Found, httpContext.Response.StatusCode);
        Assert.StartsWith(AuthorizationEndpoint, httpContext.Response.Headers.Location.ToString());
    }

    /// <summary>
    /// The load-bearing one: the state cookie is on the very response that carries the redirect, so the
    /// browser cannot arrive at the provider without already holding its binding to this login.
    /// </summary>
    [Fact]
    public async Task WritesTheStateCookieOnTheSameResponseAsTheRedirect()
    {
        var httpContext = HttpContext();

        var result = await BuilderFor(httpContext)
            .ChallengeAsync("/orders", TestContext.Current.CancellationToken);
        await result.ExecuteAsync(httpContext);

        var location = httpContext.Response.Headers.Location.ToString();
        Assert.StartsWith(AuthorizationEndpoint, location);

        // The cookie and the redirect are both on this one response.
        var cookie = Assert.Single(SetCookieHeaderValue.ParseList(httpContext.Response.Headers.SetCookie));
        Assert.True(cookie.HttpOnly);

        // And the cookie is the store for the exact state the redirect sends: the state in the request URL
        // names the cookie the callback will read.
        Assert.Contains("state=", location);
    }

    /// <summary>
    /// An absolute return address is refused by the builder, not turned into an open redirect.
    /// </summary>
    [Fact]
    public async Task RefusesAnAbsoluteReturnAddress()
    {
        var httpContext = new DefaultHttpContext();

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => BuilderFor(httpContext).ChallengeAsync(
                new Uri("https://evil.example/"), TestContext.Current.CancellationToken));
    }
}
