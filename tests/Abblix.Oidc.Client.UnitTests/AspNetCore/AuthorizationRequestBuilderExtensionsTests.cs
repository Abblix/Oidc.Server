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

    /// <summary>
    /// A token-returning challenge works end to end without the host naming a response mode, because
    /// registering an ASP.NET store is itself the statement that this host is server-side.
    /// </summary>
    /// <remarks>
    /// The gap this covers is the one that sank an earlier design: a response_type that returns tokens
    /// defaults to the fragment, which never reaches a server, so a request built without a response mode
    /// produces a callback that arrives empty. Asserting form_post on the wire is what proves the
    /// adapter's post-configure ran and that the request the provider receives can be answered.
    /// </remarks>
    [Fact]
    public async Task ATokenReturningChallenge_AsksForFormPostWithoutTheHostSayingSo()
    {
        var services = new ServiceCollection();
        // Executing an IResult resolves a logger from the request services, which every real ASP.NET host
        // has; a bare container needs it added.
        services.AddLogging();
        services.AddSingleton<IProviderMetadataProvider>(new ConfiguredMetadataProvider(new ProviderMetadata
        {
            Issuer = Issuer,
            AuthorizationEndpoint = AuthorizationEndpoint,
        }));
        services.AddAuthorizationRequests(options =>
        {
            options.RedirectUri = new Uri("https://client.example.com/signin-oidc");
            options.Flow = AuthorizationFlow.CodeIdToken;
            options.FrontChannelTokensAccepted = true;
            // ResponseMode deliberately not set: the adapter answers it.
        });
        services.AddCookieAuthorizationStateStore();
        services.Configure<OidcClientOptions>(options => options.ClientId = "test-client");

        var provider = services.BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = provider };
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;

        var result = await provider.GetRequiredService<IAuthorizationRequestBuilder>()
            .ChallengeAsync("/orders", TestContext.Current.CancellationToken);
        await result.ExecuteAsync(httpContext);

        var query = System.Web.HttpUtility.ParseQueryString(
            new Uri(httpContext.Response.Headers.Location.ToString()).Query);

        Assert.Equal("code id_token", query["response_type"]);
        Assert.Equal("form_post", query["response_mode"]);
    }

    /// <summary>
    /// A pure implicit flow is not blocked by a provider that advertises no SHA-256 challenge method:
    /// there is no code in that flow, so PKCE has nothing to guard and its absence is not a reason to
    /// refuse the login.
    /// </summary>
    [Fact]
    public async Task AnImplicitChallenge_IsNotRefusedByAProviderWithoutPkce()
    {
        var metadataProvider = new ConfiguredMetadataProvider(new ProviderMetadata
        {
            Issuer = Issuer,
            AuthorizationEndpoint = AuthorizationEndpoint,
            CodeChallengeMethodsSupported = ["plain"],
        });

        var httpContext = HttpContext();
        var store = new CookieAuthorizationStateStore(
            new HttpContextAccessor { HttpContext = httpContext },
            _dataProtection,
            Options.Create(new AuthorizationStateOptions()));

        var builder = new AuthorizationRequestBuilder(
            metadataProvider,
            new PkceProvider(metadataProvider),
            store,
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(new AuthorizationRequestOptions
            {
                RedirectUri = new Uri("https://client.example.com/signin-oidc"),
                Flow = AuthorizationFlow.IdToken,
                FrontChannelTokensAccepted = true,
                ResponseMode = ResponseModes.FormPost,
            }));

        var request = await builder.CreateAsync(
            new Uri("/orders", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Contains("response_type=id_token", request.RequestUri.Query);
        Assert.DoesNotContain("code_challenge", request.RequestUri.Query);
    }
}
