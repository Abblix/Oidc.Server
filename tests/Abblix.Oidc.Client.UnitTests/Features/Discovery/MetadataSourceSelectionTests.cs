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

using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.Discovery;

/// <summary>
/// Tests that the host names its metadata source explicitly, and that omitting the choice fails loudly rather
/// than falling back to one.
/// </summary>
public class MetadataSourceSelectionTests
{
    private static ProviderMetadata HandWrittenMetadata() => new()
    {
        Issuer = "https://oauth-only.example.com",
        AuthorizationEndpoint = "https://oauth-only.example.com/authorize",
        TokenEndpoint = "https://oauth-only.example.com/token",
    };

    private static IServiceCollection ClientCore() => new ServiceCollection()
        .AddOidcClientCore(options => options.ClientId = "test-client");

    private static IProviderMetadataProvider Resolve(IServiceCollection services) =>
        services.BuildServiceProvider().GetRequiredService<IProviderMetadataProvider>();

    /// <summary>
    /// Adding discovery registers the source that reads the provider's document.
    /// </summary>
    [Fact]
    public void AddDiscoveryRegistersTheDiscoveringSource()
    {
        var services = ClientCore()
            .AddDiscovery(options => options.Authority = new Uri("https://provider.example.com"));

        Assert.IsType<DiscoveredMetadataProvider>(Resolve(services));
    }

    /// <summary>
    /// Adding configured metadata registers the source that works from what the host declared. This is the
    /// plain OAuth 2.0 provider case, where there is no document to discover.
    /// </summary>
    [Fact]
    public async Task AddConfiguredMetadataRegistersTheConfiguredSource()
    {
        var services = ClientCore().AddConfiguredMetadata(HandWrittenMetadata());

        var metadataProvider = Resolve(services);
        Assert.IsType<ConfiguredMetadataProvider>(metadataProvider);

        var metadata = await metadataProvider.GetMetadataAsync(TestContext.Current.CancellationToken);
        Assert.Equal("https://oauth-only.example.com/token", metadata.TokenEndpoint);
    }

    /// <summary>
    /// A source chosen before the core is added survives: the core only fills the gap, it never overrides a
    /// choice the host already made.
    /// </summary>
    [Fact]
    public void AChoiceMadeBeforeTheCoreSurvives()
    {
        var services = new ServiceCollection()
            .AddConfiguredMetadata(HandWrittenMetadata())
            .AddOidcClientCore(options => options.ClientId = "test-client");

        Assert.IsType<ConfiguredMetadataProvider>(Resolve(services));
    }

    /// <summary>
    /// Omitting the choice fails with a message naming both calls, rather than silently defaulting to one.
    /// Reading endpoints from a document and reading them from configuration are different trust models, so
    /// neither is safe to pick on the host's behalf.
    /// </summary>
    [Fact]
    public async Task OmittingTheChoiceFailsLoudly()
    {
        var metadataProvider = Resolve(ClientCore());
        Assert.IsType<MetadataSourceNotChosenProvider>(metadataProvider);

        var exception = await Assert.ThrowsAsync<ProviderMetadataException>(
            () => metadataProvider.GetMetadataAsync(TestContext.Current.CancellationToken));

        Assert.Contains("AddDiscovery", exception.Message);
        Assert.Contains("AddConfiguredMetadata", exception.Message);
    }
}
