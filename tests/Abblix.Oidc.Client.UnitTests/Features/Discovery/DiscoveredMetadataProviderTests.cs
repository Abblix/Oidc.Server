// Abblix OIDC Server Library
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

using System.Net;
using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.Discovery;

/// <summary>
/// Tests for <see cref="DiscoveredMetadataProvider"/>.
/// </summary>
public class DiscoveredMetadataProviderTests
{
    private const string Authority = "https://provider.example.com";

    private static string MetadataJson(string issuer) =>
        $$"""
          {
            "issuer": "{{issuer}}",
            "authorization_endpoint": "{{Authority}}/authorize",
            "token_endpoint": "{{Authority}}/token",
            "jwks_uri": "{{Authority}}/jwks",
            "code_challenge_methods_supported": ["S256"],
            "a_member_this_client_does_not_model": "kept"
          }
          """;

    private static DiscoveredMetadataProvider CreateProvider(
        StubHttpMessageHandler handler,
        TimeProvider timeProvider,
        Uri? authority = null,
        Uri? metadataAddress = null,
        TimeSpan? cacheLifetime = null)
    {
        var options = new DiscoveryOptions
        {
            Authority = authority ?? new Uri(Authority),
            MetadataAddress = metadataAddress,
        };

        if (cacheLifetime is { } lifetime)
            options.MetadataCacheLifetime = lifetime;

        return new DiscoveredMetadataProvider(
            new StubHttpClientFactory(handler),
            timeProvider,
            Options.Create(options));
    }

    /// <summary>
    /// The document is read from the well-known path under the configured authority.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_ReadsTheWellKnownPathUnderTheAuthority()
    {
        var handler = new StubHttpMessageHandler(MetadataJson(Authority));

        var metadata = await CreateProvider(handler, TimeProvider.System)
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(
            new Uri($"{Authority}/.well-known/openid-configuration"),
            Assert.Single(handler.RequestedAddresses));

        Assert.Equal(Authority, metadata.Issuer);
        Assert.Equal($"{Authority}/jwks", metadata.JsonWebKeySetUri);
    }

    /// <summary>
    /// An authority that carries a path segment keeps it: multi-tenant providers publish the document below
    /// the tenant path, not at the host root.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_KeepsThePathSegmentOfTheAuthority()
    {
        const string tenantAuthority = "https://provider.example.com/tenant-one";
        var handler = new StubHttpMessageHandler(MetadataJson(tenantAuthority));

        await CreateProvider(handler, TimeProvider.System, new Uri(tenantAuthority))
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(
            new Uri($"{tenantAuthority}/.well-known/openid-configuration"),
            Assert.Single(handler.RequestedAddresses));
    }

    /// <summary>
    /// A document that names an issuer other than the authority it was served from is rejected, per OpenID
    /// Connect Discovery 1.0 section 4.3. This is the check that stops a provider from borrowing another
    /// issuer's name and having every later token validation measured against it.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_RejectsAnIssuerThatDoesNotMatchTheAuthority()
    {
        var handler = new StubHttpMessageHandler(MetadataJson("https://attacker.example.com"));

        var exception = await Assert.ThrowsAsync<ProviderMetadataException>(
            () => CreateProvider(handler, TimeProvider.System)
                .GetMetadataAsync(TestContext.Current.CancellationToken));

        Assert.Contains("attacker.example.com", exception.Message);
    }

    /// <summary>
    /// A document that declares no issuer at all is rejected: there would be nothing to check later tokens
    /// against.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_RejectsADocumentWithoutAnIssuer()
    {
        var handler = new StubHttpMessageHandler("""{ "token_endpoint": "https://provider.example.com/token" }""");

        await Assert.ThrowsAsync<ProviderMetadataException>(
            () => CreateProvider(handler, TimeProvider.System)
                .GetMetadataAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A transport failure surfaces as a discovery failure rather than a raw HTTP exception, so a host can
    /// tell an unreachable provider from a protocol error.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_TranslatesATransportFailure()
    {
        var handler = new StubHttpMessageHandler(string.Empty, HttpStatusCode.ServiceUnavailable);

        var exception = await Assert.ThrowsAsync<ProviderMetadataException>(
            () => CreateProvider(handler, TimeProvider.System)
                .GetMetadataAsync(TestContext.Current.CancellationToken));

        Assert.IsType<HttpRequestException>(exception.InnerException);
    }

    /// <summary>
    /// A second call within the cache lifetime is served from the cached copy, so discovery is not a
    /// per-request cost.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_ServesTheSecondCallFromCache()
    {
        var handler = new StubHttpMessageHandler(MetadataJson(Authority));
        var provider = CreateProvider(handler, new FakeTimeProvider());

        await provider.GetMetadataAsync(TestContext.Current.CancellationToken);
        await provider.GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Single(handler.RequestedAddresses);
    }

    /// <summary>
    /// Once the lifetime elapses the document is read again, bounding how long the client keeps following a
    /// provider that has moved an endpoint.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_RefetchesAfterTheCacheLifetimeElapses()
    {
        var handler = new StubHttpMessageHandler(MetadataJson(Authority));
        var timeProvider = new FakeTimeProvider();
        var provider = CreateProvider(handler, timeProvider, cacheLifetime: TimeSpan.FromMinutes(10));

        await provider.GetMetadataAsync(TestContext.Current.CancellationToken);
        timeProvider.Advance(TimeSpan.FromMinutes(11));
        await provider.GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, handler.RequestedAddresses.Count);
    }

    /// <summary>
    /// A failed fetch is not cached: the next call retries instead of repeating the failure for the whole
    /// cache lifetime.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_DoesNotCacheAFailure()
    {
        var handler = new StubHttpMessageHandler(string.Empty, HttpStatusCode.ServiceUnavailable);
        var provider = CreateProvider(handler, new FakeTimeProvider());

        await Assert.ThrowsAsync<ProviderMetadataException>(
            () => provider.GetMetadataAsync(TestContext.Current.CancellationToken));

        handler.RespondWith(MetadataJson(Authority), HttpStatusCode.OK);
        var metadata = await provider.GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(Authority, metadata.Issuer);
    }

    /// <summary>
    /// A member the client does not model is preserved rather than discarded, so a provider capability the
    /// base client has no opinion about stays readable.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_KeepsMembersItDoesNotModel()
    {
        var handler = new StubHttpMessageHandler(MetadataJson(Authority));

        var metadata = await CreateProvider(handler, TimeProvider.System)
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(metadata.AdditionalMetadata);
        Assert.True(metadata.AdditionalMetadata.ContainsKey("a_member_this_client_does_not_model"));
    }

    /// <summary>
    /// An explicitly configured metadata address is read verbatim, for a provider that publishes the document
    /// somewhere other than the well-known path.
    /// </summary>
    [Fact]
    public async Task GetMetadataAsync_ReadsAnExplicitMetadataAddressVerbatim()
    {
        var address = new Uri($"{Authority}/custom/metadata.json");
        var handler = new StubHttpMessageHandler(MetadataJson(Authority));

        await CreateProvider(handler, TimeProvider.System, metadataAddress: address)
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(address, Assert.Single(handler.RequestedAddresses));
    }
}
