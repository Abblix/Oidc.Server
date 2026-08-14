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

using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The two opt-in shapes of the discovery document through this adapter: mutual-TLS endpoint aliases
/// (RFC 8705 section 5) and signed metadata (RFC 8414 section 2.1).
/// </summary>
/// <remarks>
/// Both are off by default, so the shared host never reaches them, and the MVC side is covered by unit tests
/// over its controller that have no Minimal API counterpart - which is how one adapter came to publish these
/// and the other to have neither of them exercised.
///
/// They are worth pinning for what a mistake costs. An mTLS alias sends a client's certificate-bound traffic
/// to whatever host the document names, so a wrong base leaks nothing but breaks every certificate-bound
/// client; and signed metadata exists precisely so a client need not trust the transport, which makes a
/// document that claims to be signed but is not, or is signed unverifiably, worse than one that never claimed
/// it.
/// </remarks>
public sealed class DiscoveryMetadataTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private static readonly Uri MtlsBaseUri = new("https://mtls.example.com");

    private HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestFactory.BaseAddress,
        });

    private WebApplicationFactory<Program> HostWith(Action<OidcOptions> configure)
        => factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.PostConfigure(configure)));

    /// <summary>
    /// With a mutual-TLS base configured, the document gains an alias block naming the same endpoints on that
    /// host, so a client holding a certificate knows where to present it. The paths must survive the rebase:
    /// an alias pointing at the right host but the wrong path is a 404 for every certificate-bound client.
    /// </summary>
    [Fact]
    public async Task A_configured_mtls_base_publishes_aliases_on_that_host_with_the_same_paths()
    {
        await using var host = HostWith(options => options.Discovery.MtlsBaseUri = MtlsBaseUri);
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        var aliases = discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]?.AsObject();
        Assert.NotNull(aliases);

        var aliasedToken = new Uri(
            aliases[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>());
        var token = new Uri(OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint));

        Assert.Equal(MtlsBaseUri.GetLeftPart(UriPartial.Authority), aliasedToken.GetLeftPart(UriPartial.Authority));
        Assert.Equal(token.AbsolutePath, aliasedToken.AbsolutePath);
    }

    /// <summary>
    /// The default document publishes no alias block at all. Publishing one unasked would advertise a
    /// mutual-TLS endpoint no deployment configured, sending certificate-bound clients at a host that does not
    /// answer.
    /// </summary>
    [Fact]
    public async Task Without_an_mtls_base_the_document_carries_no_aliases()
    {
        var client = CreateClientFor(factory);

        var discovery = await client.FetchDiscoveryAsync();

        Assert.Null(discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]);
    }

    /// <summary>
    /// RFC 8414 section 2.1: with signed metadata enabled the document carries a <c>signed_metadata</c> JWT
    /// whose claims restate the document. The signature is verified against the provider's published keys,
    /// because a client's whole reason to read it is that it does not want to trust the transport - a token
    /// that merely looks like a JWT would pass a shape check and fail the client.
    /// </summary>
    [Fact]
    public async Task Signed_metadata_is_published_and_verifies_against_the_published_keys()
    {
        await using var host = HostWith(options => options.Discovery.SignedMetadata = true);
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        var signed = discovery[ConfigurationResponse.Parameters.SignedMetadata]?.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(signed), "signed metadata was enabled but the document carried none");

        var jwksUri = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.JwksUri);
        var serverJwks = JsonSerializer.Deserialize<JsonWebKeySet>(
            await client.GetStringAsync(jwksUri, TestContext.Current.CancellationToken));
        Assert.NotNull(serverJwks);

        var issuer = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.Issuer);

        var result = await CreateValidator().ValidateAsync(signed, new ValidationParameters
        {
            // RFC 8414 section 2.1 makes iss REQUIRED in signed metadata and says nothing about aud, so the
            // audience requirement is dropped rather than satisfied with a permissive delegate: demanding a
            // claim the specification does not is how a conforming document gets rejected.
            Options = ValidationOptions.Default & ~ValidationOptions.RequireValidAudience,
            ValidateIssuer = iss => Task.FromResult(iss.TrimEnd('/') == issuer.TrimEnd('/')),
            ResolveIssuerSigningKeys = _ => serverJwks.Keys.ToAsyncEnumerable(),
        });

        Assert.True(result.TryGetSuccess(out var token),
            result.TryGetFailure(out var error)
                ? $"the signed metadata did not validate: {error.Error} - {error.ErrorDescription}"
                : "the signed metadata did not validate");

        // The point of the signature is that it covers the document, so the claims have to restate it rather
        // than merely be well-formed: an issuer that disagreed with the one beside it is what a client checks.
        Assert.Equal(issuer.TrimEnd('/'), token.Payload.Issuer?.TrimEnd('/'));
    }

    /// <summary>
    /// And by default the member is absent, since a client that finds it will try to verify it.
    /// </summary>
    [Fact]
    public async Task Without_the_option_the_document_carries_no_signed_metadata()
    {
        var client = CreateClientFor(factory);

        var discovery = await client.FetchDiscoveryAsync();

        Assert.Null(discovery[ConfigurationResponse.Parameters.SignedMetadata]);
    }

    private static IJsonWebTokenValidator CreateValidator()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider().GetRequiredService<IJsonWebTokenValidator>();
    }
}
