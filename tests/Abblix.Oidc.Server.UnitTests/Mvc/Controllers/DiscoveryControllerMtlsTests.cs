// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Mvc.Controllers;

/// <summary>
/// Unit tests for <see cref="ConfigurationResponseFormatter"/> verifying RFC 8705
/// mTLS endpoint aliases computed from the issuer's mutual TLS host.
/// </summary>
public class DiscoveryControllerMtlsTests
{
    private readonly Mock<IOptionsSnapshot<OidcOptions>> _optionsMock;
    private readonly Mock<IOidcEndpointResolver> _endpointResolverMock;
    private readonly ConfigurationResponseFormatter _formatter;
    private readonly OidcOptions _oidcOptions;
    private readonly TestIssuer _issuer = new();

    public DiscoveryControllerMtlsTests()
    {
        _optionsMock = new Mock<IOptionsSnapshot<OidcOptions>>();
        _endpointResolverMock = new Mock<IOidcEndpointResolver>();

        _oidcOptions = new OidcOptions
        {
            Discovery = new DiscoveryOptions
            {
                AllowEndpointPathsDiscovery = true,
            },
            EnabledEndpoints = OidcEndpoints.Token | OidcEndpoints.Revocation |
                              OidcEndpoints.Introspection | OidcEndpoints.UserInfo,
        };

        _optionsMock.Setup(x => x.Value).Returns(_oidcOptions);

        SetupEndpointResolver();

        // SignedMetadata defaults off in these fixtures, so the signing collaborator is
        // never exercised - supplied only to satisfy the constructor.
        _formatter = new ConfigurationResponseFormatter(
            _optionsMock.Object,
            _endpointResolverMock.Object,
            Mock.Of<ISignedMetadataProvider>(),
            SingleIssuer.SettingsOf(() => _issuer, _oidcOptions));
    }

    /// <summary>
    /// The smallest handler output the formatter will accept: the four members OpenID Connect Discovery 1.0
    /// section 3 marks REQUIRED, and nothing else. These tests are about mTLS aliases, so every other field is
    /// left absent on purpose - which is now expressible, because absent and empty are different states.
    /// </summary>
    private static ConfigurationResponse MinimalResponse() => new()
    {
        Issuer = new Uri("https://example.com"),
        ResponseTypesSupported = ["code"],
        IdTokenSigningAlgValuesSupported = ["RS256"],
        SubjectTypesSupported = ["public"],
    };

    /// <summary>
    /// Verifies no mTLS aliases when no MtlsBaseUri is configured.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithNoMtlsConfiguration_ShouldNotIncludeMtlsAliases()
    {
        // Arrange - base response without URLs (simulating handler output)
        var baseResponse = MinimalResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.MtlsEndpointAliases);
    }

    /// <summary>
    /// A document fetched on the mutual-TLS host names the ordinary endpoints on the issuer's host, so a client
    /// without a certificate that follows it is not sent to the host demanding one; the aliases stay on the
    /// mutual-TLS host.
    /// </summary>
    [Theory]
    [InlineData("https://mtls.example.com", "https://mtls.example.com/token")]
    [InlineData("https://mtls.example.com", "https://mtls.example.com:8443/token")] // another port, the same host
    [InlineData("https://mtls.example.com", "https://mtls.example.com./token")] // the fully qualified form
    [InlineData("https://мтлс.example.com", "https://xn--k1abqc.example.com/token")] // the ASCII form of the name
    public async Task ADocumentFetchedOnTheMutualTlsHost_NamesTheOrdinaryEndpointsOnTheIssuersHost(
        string mtlsBaseUri,
        string resolved)
    {
        _issuer.MtlsBaseUri = new Uri(mtlsBaseUri);
        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.Token))
            .Returns(new Uri(resolved));

        var result = await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.NotNull(result.Value);
        Assert.Equal(new Uri("https://example.com/token"), result.Value.TokenEndpoint);
        Assert.Equal(new Uri(new Uri(mtlsBaseUri), "/token"), result.Value.MtlsEndpointAliases?.TokenEndpoint);
    }

    /// <summary>
    /// An endpoint's path is kept exactly as resolved on whichever host it is moved to: a path opening with an empty
    /// segment stays a path rather than naming a host, and an escaped character stays escaped, so the alias and the
    /// ordinary endpoint reach the address the tenant is resolved at.
    /// </summary>
    [Theory]
    [InlineData("https://example.com//t1/token", "https://mtls.example.com//t1/token", "https://example.com//t1/token")]
    [InlineData("https://mtls.example.com//t1/token", "https://mtls.example.com//t1/token", "https://example.com//t1/token")]
    [InlineData("https://example.com/t%2Fa/token", "https://mtls.example.com/t%2Fa/token", "https://example.com/t%2Fa/token")]
    public async Task AnEndpointsPath_IsKeptAsResolved_OnTheHostItIsMovedTo(
        string resolved,
        string alias,
        string ordinary)
    {
        _issuer.MtlsBaseUri = new Uri("https://mtls.example.com");
        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.Token))
            .Returns(new Uri(resolved));

        var result = await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.NotNull(result.Value);
        Assert.Equal(alias, result.Value.MtlsEndpointAliases?.TokenEndpoint?.OriginalString);
        Assert.Equal(ordinary, result.Value.TokenEndpoint?.OriginalString);
    }

    /// <summary>
    /// Verifies mTLS aliases are auto-computed when only MtlsBaseUri is configured.
    /// Tests RFC 8705 auto-computation feature.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithMtlsBaseUriOnly_ShouldAutoComputeAliases()
    {
        // Arrange
        _issuer.MtlsBaseUri = new Uri("https://mtls.example.com");
        var baseResponse = MinimalResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/revocation"), result.Value.MtlsEndpointAliases.RevocationEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/introspection"), result.Value.MtlsEndpointAliases.IntrospectionEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/userinfo"), result.Value.MtlsEndpointAliases.UserInfoEndpoint);
    }

    /// <summary>
    /// Verifies mTLS aliases are null when standard endpoints are disabled.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithDisabledEndpoints_ShouldHaveNullMtlsAliases()
    {
        // Arrange
        _issuer.MtlsBaseUri = new Uri("https://mtls.example.com");
        _oidcOptions.EnabledEndpoints = 0; // Disable all endpoints
        var baseResponse = MinimalResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.TokenEndpoint);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Null(result.Value.MtlsEndpointAliases.TokenEndpoint); // Null because standard endpoint is null
    }

    /// <summary>
    /// Verifies mTLS port and scheme are preserved from base URI.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithMtlsBaseUriDifferentPort_ShouldPreservePort()
    {
        // Arrange
        _issuer.MtlsBaseUri = new Uri("https://mtls.example.com:8443");
        var baseResponse = MinimalResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com:8443/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(8443, result.Value.MtlsEndpointAliases.TokenEndpoint!.Port);
    }

    /// <summary>
    /// Verifies the RFC 8705 section 3.3 tls_client_certificate_bound_access_tokens flag surfaces in the
    /// formatted discovery document when the handler advertised support.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithCertificateBoundTokensSupported_ShouldSurfaceFlag()
    {
        // Arrange
        var baseResponse = MinimalResponse() with { TlsClientCertificateBoundAccessTokens = true };

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.True(result.Value.TlsClientCertificateBoundAccessTokens);
    }

    /// <summary>
    /// Verifies the flag is omitted (null) when the provider does not advertise certificate-bound
    /// token support, so the discovery document carries no misleading "false".
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithoutCertificateBoundTokens_ShouldOmitFlag()
    {
        // Arrange
        var baseResponse = MinimalResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.TlsClientCertificateBoundAccessTokens);
    }

    private void SetupEndpointResolver()
    {
        // Setup endpoint resolver to return predictable URIs
        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.Token))
            .Returns(new Uri("https://example.com/token"));

        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.Revocation))
            .Returns(new Uri("https://example.com/revocation"));

        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.Introspection))
            .Returns(new Uri("https://example.com/introspection"));

        _endpointResolverMock
            .Setup(x => x.Resolve(OidcEndpoints.UserInfo))
            .Returns(new Uri("https://example.com/userinfo"));
    }
}
