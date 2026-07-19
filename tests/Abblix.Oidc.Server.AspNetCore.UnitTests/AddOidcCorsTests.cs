// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// Unit coverage for the shared <see cref="CorsServiceCollectionExtensions.AddOidcCors"/> that both transport
/// adapters call: the default policy, the host-wins override, the <see cref="OidcCorsOptions"/> supplement, and
/// idempotency when more than one adapter registers it. The adapters' end-to-end wiring is covered separately in
/// each adapter's E2E suite.
/// </summary>
public class AddOidcCorsTests
{
    private static CorsPolicy? BuildOidcPolicy(Action<IServiceCollection>? afterAddOidcCors = null)
    {
        var services = new ServiceCollection();
        services.AddOidcCors();
        afterAddOidcCors?.Invoke(services);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<CorsOptions>>().Value;
        return options.GetPolicy(OidcConstants.CorsPolicyName);
    }

    [Fact]
    public void Default_policy_allows_any_origin_without_credentials()
    {
        var policy = BuildOidcPolicy();

        Assert.NotNull(policy);
        Assert.True(policy!.AllowAnyOrigin);
        Assert.False(policy.SupportsCredentials);
    }

    [Fact]
    public void Configured_origins_narrow_the_default()
    {
        var policy = BuildOidcPolicy(services =>
            services.Configure<OidcCorsOptions>(o => o.AllowedOrigins.Add("https://spa.example.com")));

        Assert.NotNull(policy);
        Assert.False(policy!.AllowAnyOrigin);
        Assert.Equal(["https://spa.example.com"], policy.Origins);
    }

    [Fact]
    public void Host_policy_of_the_same_name_wins()
    {
        // The host defines OidcCorsPolicy after AddOidcCors; the post-configure fills the default only when the
        // host has not, so the host's policy survives regardless of registration order.
        var policy = BuildOidcPolicy(services => services.AddCors(o => o.AddPolicy(
            OidcConstants.CorsPolicyName, p => p.WithOrigins("https://trusted.example.com"))));

        Assert.NotNull(policy);
        Assert.False(policy!.AllowAnyOrigin);
        Assert.Equal(["https://trusted.example.com"], policy.Origins);
    }

    [Fact]
    public void Registering_twice_still_yields_the_default()
    {
        // Both adapters may call AddOidcCors; TryAddEnumerable dedups the post-configure, so the default applies once.
        var policy = BuildOidcPolicy(services => services.AddOidcCors());

        Assert.NotNull(policy);
        Assert.True(policy!.AllowAnyOrigin);
    }
}
