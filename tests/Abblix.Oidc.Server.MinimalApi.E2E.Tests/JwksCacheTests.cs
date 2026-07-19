// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// End-to-end guard that the Minimal API adapter advertises the JWKS endpoint as cacheable with a lifetime equal
/// to the key-rollover propagation window (<c>OidcOptions.KeyRolloverPropagation</c>, one hour by default),
/// overriding the group-wide no-cache policy for this one endpoint. A client honouring the header is then never
/// staler than that window, which makes a signing-key rotation zero-downtime.
/// </summary>
public sealed class JwksCacheTests(TestFactory factory) : IClassFixture<TestFactory>
{
    [Fact]
    public async Task Jwks_is_cacheable_for_the_rollover_propagation_window()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestFactory.BaseAddress,
        });

        var response = await client.GetAsync("/.well-known/jwks", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var cacheControl = response.Headers.CacheControl;
        Assert.NotNull(cacheControl);
        Assert.True(cacheControl!.Public);
        Assert.Equal(TimeSpan.FromHours(1), cacheControl.MaxAge); // the default KeyRolloverPropagation window
        Assert.False(cacheControl.NoStore);
        Assert.False(cacheControl.NoCache);
    }
}
