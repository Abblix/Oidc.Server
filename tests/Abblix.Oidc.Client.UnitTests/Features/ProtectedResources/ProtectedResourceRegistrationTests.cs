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

using Abblix.Oidc.Client.Common.Constants;
using Abblix.Oidc.Client.Features.ProtectedResources;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.ProtectedResources;

/// <summary>
/// What a host is allowed to wire, and what it is stopped from wiring.
/// </summary>
public class ProtectedResourceRegistrationTests
{
    private const string Resource = "https://api.example.com/orders";

    private sealed class StubTokenSource : IAccessTokenSource
    {
        public Task<AccessToken> GetTokenAsync(
            AccessTokenRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(new AccessToken("the-token", TokenTypes.Bearer));
    }

    private static IServiceCollection Wired(string? resource = Resource)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddHttpClient("orders")
            .AddAccessToken(options =>
                options.Resource = resource is null ? null : new Uri(resource, UriKind.RelativeOrAbsolute));

        return services;
    }

    private static HttpClient CreateClient(IServiceCollection services)
        => services.BuildServiceProvider()
            .GetRequiredService<IHttpClientFactory>()
            .CreateClient("orders");

    /// <summary>
    /// A host that wired a resource client but never said where tokens come from is refused by name at the
    /// first call, rather than sending an unauthenticated request the API answers 401.
    /// </summary>
    [Fact]
    public async Task WithoutASourceTheFirstCallIsRefusedByName()
    {
        using var client = CreateClient(Wired());

        var exception = await Assert.ThrowsAsync<AccessTokenUnavailableException>(
            () => client.GetAsync($"{Resource}/42", TestContext.Current.CancellationToken));

        Assert.Contains("AddSessionAccessTokenSource", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A source registered as scoped is refused. This is the one defect no container validation catches: it
    /// resolves perfectly legally inside the handler's own scope, so both <c>ValidateScopes</c> and
    /// <c>ValidateOnBuild</c> stay silent, and the instance the handler captured then serves every caller
    /// for the minutes it is pooled - one user's token presented for another.
    /// </summary>
    /// <remarks>
    /// It fires when the handler chain is built, which is when the client is first created - earlier than
    /// the first call, and the earliest moment the registrations can be read.
    /// </remarks>
    [Fact]
    public void AScopedSourceIsRefused()
    {
        var services = Wired();
        services.AddScoped<IAccessTokenSource, StubTokenSource>();

        var exception = Assert.Throws<AccessTokenPresentationException>(() => CreateClient(services));

        Assert.Contains("Scoped", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A singleton source is accepted, which is what makes the case above a check rather than a blanket
    /// refusal.
    /// </summary>
    [Fact]
    public void ASingletonSourceIsAccepted()
    {
        var services = Wired();
        services.AddAccessTokenSource<StubTokenSource>();

        using var client = CreateClient(services);

        Assert.NotNull(client);
    }

    /// <summary>
    /// Saying where tokens come from wins whichever order the two calls were made in, which is what
    /// replacing rather than adding buys.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheSourceWinsInEitherOrder(bool sourceFirst)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        if (sourceFirst)
            services.AddAccessTokenSource<StubTokenSource>();

        services.AddProtectedResourceAccess();

        if (!sourceFirst)
            services.AddAccessTokenSource<StubTokenSource>();

        Assert.IsType<StubTokenSource>(
            services.BuildServiceProvider().GetRequiredService<IAccessTokenSource>());
    }

    /// <summary>
    /// A resource address a token could not safely be scoped to is refused. A relative one has no origin to
    /// compare, a plain-HTTP one would carry the token in the clear, a fragment is forbidden by RFC 8707
    /// section 2, and a query cannot act as a path prefix.
    /// </summary>
    [Theory]
    [InlineData("/orders")]
    [InlineData("http://api.example.com/orders")]
    [InlineData("https://api.example.com/orders#part")]
    [InlineData("https://api.example.com/orders?tenant=acme")]
    public void AnUnusableResourceIsRefused(string resource)
    {
        var services = Wired(resource);
        services.AddAccessTokenSource<StubTokenSource>();

        Assert.Throws<AccessTokenPresentationException>(() => CreateClient(services));
    }

    /// <summary>
    /// A client that names no resource at all is refused the same way.
    /// </summary>
    [Fact]
    public void AClientWithNoResourceIsRefused()
    {
        var services = Wired(resource: null);
        services.AddAccessTokenSource<StubTokenSource>();

        Assert.Throws<AccessTokenPresentationException>(() => CreateClient(services));
    }
}
