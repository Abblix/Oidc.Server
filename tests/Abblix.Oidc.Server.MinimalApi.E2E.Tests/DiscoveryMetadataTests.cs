// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Abblix.Oidc.Server.E2E.Tests;

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

    // Both derived from the one host above, so a deployment shape is described by its PATH here
    // rather than by repeating an address the file already names.
    private static readonly Uri MtlsGatewayBase = new(MtlsBaseUri, "/gateway");
    private static readonly Uri DedicatedTokenAlias = new(MtlsBaseUri, "/dedicated/token");

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
    /// An explicitly named alias wins over the one the base URI would compute. A deployment that sets both is
    /// saying the mutual-TLS endpoint is not simply the same path on another host, and rebasing over that would
    /// publish an address the operator deliberately did not choose.
    /// </summary>
    [Fact]
    public async Task An_explicit_alias_wins_over_the_one_the_base_uri_would_compute()
    {
        var chosen = DedicatedTokenAlias;
        await using var host = HostWith(options =>
        {
            options.Discovery.MtlsBaseUri = MtlsBaseUri;
            options.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions { TokenEndpoint = chosen };
        });
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        var aliases = discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]?.AsObject();
        Assert.NotNull(aliases);
        Assert.Equal(
            chosen.AbsoluteUri,
            aliases[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>());

        // The endpoints left unnamed still follow the base, so setting one alias does not silently drop the rest.
        var revocation = new Uri(aliases[ConfigurationResponse.Parameters.RevocationEndpoint]!.GetValue<string>());
        Assert.Equal(MtlsBaseUri.GetLeftPart(UriPartial.Authority), revocation.GetLeftPart(UriPartial.Authority));
    }

    /// <summary>
    /// A base URI carrying a path prefix keeps that prefix and the endpoint path, joined by exactly one
    /// separator. Deployments put the mutual-TLS listener behind a gateway path rather than on its own host, and
    /// a doubled or dropped slash there is a 404 for every certificate-bound client - the kind of mistake a test
    /// asserting only the host would not see.
    /// </summary>
    [Fact]
    public async Task An_mtls_base_with_a_path_keeps_the_prefix_and_the_endpoint_path()
    {
        var gateway = MtlsGatewayBase;
        await using var host = HostWith(options => options.Discovery.MtlsBaseUri = gateway);
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        var aliases = discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]?.AsObject();
        Assert.NotNull(aliases);

        var token = new Uri(OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.TokenEndpoint));
        var aliased = new Uri(aliases[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>());

        Assert.Equal($"/gateway{token.AbsolutePath}", aliased.AbsolutePath);
        Assert.DoesNotContain("//", aliased.AbsolutePath, StringComparison.Ordinal);
    }

    /// <summary>
    /// Named aliases with no base at all: the endpoints nobody named keep their ordinary addresses rather than
    /// vanishing or being invented. A deployment that exposes one endpoint over mutual TLS is not thereby
    /// claiming the others moved, and dropping them from the block would tell a client the opposite.
    /// </summary>
    [Fact]
    public async Task Named_aliases_without_a_base_leave_the_other_endpoints_where_they_are()
    {
        await using var host = HostWith(options =>
            options.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions { TokenEndpoint = DedicatedTokenAlias });
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        var aliases = discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]?.AsObject();
        Assert.NotNull(aliases);
        Assert.Equal(
            DedicatedTokenAlias.AbsoluteUri,
            aliases[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>());

        // With nothing to rebase onto, an unnamed alias is the ordinary endpoint itself.
        Assert.Equal(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.UserInfoEndpoint),
            aliases[ConfigurationResponse.Parameters.UserInfoEndpoint]!.GetValue<string>());
    }

    /// <summary>
    /// An endpoint switched off is absent from the alias block as well as from the document. Advertising a
    /// mutual-TLS address for an endpoint this deployment does not serve sends certificate-bound clients at a
    /// path that answers 404, and they would have no way to tell that from a misconfigured certificate.
    /// </summary>
    [Fact]
    public async Task A_disabled_endpoint_is_missing_from_the_alias_block_too()
    {
        await using var host = HostWith(options =>
        {
            options.Discovery.MtlsBaseUri = MtlsBaseUri;
            options.EnabledEndpoints &= ~OidcEndpoints.Revocation;
        });
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        Assert.Null(discovery[ConfigurationResponse.Parameters.RevocationEndpoint]);

        var aliases = discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]?.AsObject();
        Assert.NotNull(aliases);
        Assert.Null(aliases[ConfigurationResponse.Parameters.RevocationEndpoint]);

        // The endpoints still served keep their aliases, so switching one off does not empty the block.
        Assert.NotNull(aliases[ConfigurationResponse.Parameters.TokenEndpoint]);
    }

    /// <summary>
    /// With endpoint path discovery switched off the document names no endpoint addresses at all - not the
    /// ordinary ones and not the mutual-TLS aliases. The option exists for deployments that hand their clients
    /// addresses out of band, and publishing them anyway would defeat the only reason to set it.
    /// </summary>
    [Fact]
    public async Task With_path_discovery_off_the_document_names_no_endpoint_addresses()
    {
        await using var host = HostWith(options =>
        {
            options.Discovery.AllowEndpointPathsDiscovery = false;
            options.Discovery.MtlsBaseUri = MtlsBaseUri;
        });
        var client = CreateClientFor(host);

        var discovery = await client.FetchDiscoveryAsync();

        Assert.Null(discovery[ConfigurationResponse.Parameters.TokenEndpoint]);
        Assert.Null(discovery[ConfigurationResponse.Parameters.UserInfoEndpoint]);

        // The issuer stays: it identifies the provider rather than locating an endpoint, and a client that
        // cannot read it cannot validate a token from this server at all.
        Assert.NotNull(discovery[ConfigurationResponse.Parameters.Issuer]);
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
