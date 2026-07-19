// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end guard that the MVC adapter advertises the JWKS endpoint as cacheable with a lifetime equal to the
/// key-rollover propagation window (<c>OidcOptions.KeyRolloverPropagation</c>, one hour by default). A client
/// honouring the header is then never staler than that window, which is what makes a signing-key rotation
/// zero-downtime: the new key's public half is cached before the server starts producing tokens with it. This
/// pins the deliberate exception to the discovery controller's otherwise no-store metadata policy.
/// </summary>
public class JwksCacheTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Jwks_is_cacheable_for_the_rollover_propagation_window()
    {
        var client = CreateClient();

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
