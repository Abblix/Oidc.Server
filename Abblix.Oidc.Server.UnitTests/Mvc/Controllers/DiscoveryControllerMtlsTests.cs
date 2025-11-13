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

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Mvc.Controllers;

/// <summary>
/// Unit tests for <see cref="ConfigurationResponseFormatter"/> verifying RFC 8705
/// mTLS endpoint alias auto-computation and configuration.
/// </summary>
public class DiscoveryControllerMtlsTests
{
    private readonly Mock<IOptionsSnapshot<OidcOptions>> _optionsMock;
    private readonly Mock<IEndpointResolver> _endpointResolverMock;
    private readonly ConfigurationResponseFormatter _formatter;
    private readonly OidcOptions _oidcOptions;

    public DiscoveryControllerMtlsTests()
    {
        _optionsMock = new Mock<IOptionsSnapshot<OidcOptions>>();
        _endpointResolverMock = new Mock<IEndpointResolver>();

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

        _formatter = new ConfigurationResponseFormatter(_optionsMock.Object, _endpointResolverMock.Object);
    }

    /// <summary>
    /// Verifies no mTLS aliases when neither MtlsEndpointAliases nor MtlsBaseUri configured.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithNoMtlsConfiguration_ShouldNotIncludeMtlsAliases()
    {
        // Arrange - base response without URLs (simulating handler output)
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.MtlsEndpointAliases);
    }

    /// <summary>
    /// Verifies mTLS aliases are auto-computed when only MtlsBaseUri is configured.
    /// Tests RFC 8705 auto-computation feature.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithMtlsBaseUriOnly_ShouldAutoComputeAliases()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        var baseResponse = new ConfigurationResponse();

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
    /// Verifies explicit mTLS aliases are used when configured.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithExplicitMtlsAliases_ShouldUseExplicitValues()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions
        {
            TokenEndpoint = new Uri("https://mtls.example.com/custom-token"),
            RevocationEndpoint = new Uri("https://mtls.example.com/custom-revocation"),
            IntrospectionEndpoint = new Uri("https://mtls.example.com/custom-introspection"),
            UserInfoEndpoint = new Uri("https://mtls.example.com/custom-userinfo"),
        };
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com/custom-token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/custom-revocation"), result.Value.MtlsEndpointAliases.RevocationEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/custom-introspection"), result.Value.MtlsEndpointAliases.IntrospectionEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/custom-userinfo"), result.Value.MtlsEndpointAliases.UserInfoEndpoint);
    }

    /// <summary>
    /// Verifies explicit aliases take precedence over auto-computed ones.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithBothExplicitAndBaseUri_ShouldPreferExplicit()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        _oidcOptions.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions
        {
            TokenEndpoint = new Uri("https://custom.example.com/token"),
            // Others not set - should be auto-computed
        };
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://custom.example.com/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/revocation"), result.Value.MtlsEndpointAliases.RevocationEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/introspection"), result.Value.MtlsEndpointAliases.IntrospectionEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/userinfo"), result.Value.MtlsEndpointAliases.UserInfoEndpoint);
    }

    /// <summary>
    /// Verifies mTLS base URI with path is handled correctly.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithMtlsBaseUriWithPath_ShouldCombinePaths()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com/oauth");
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com/oauth/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/oauth/revocation"), result.Value.MtlsEndpointAliases.RevocationEndpoint);
    }

    /// <summary>
    /// Verifies mTLS base URI with trailing slash is normalized.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithMtlsBaseUriTrailingSlash_ShouldNormalizePath()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com/oauth/");
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com/oauth/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
    }

    /// <summary>
    /// Verifies mTLS aliases are null when standard endpoints are disabled.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithDisabledEndpoints_ShouldHaveNullMtlsAliases()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        _oidcOptions.EnabledEndpoints = 0; // Disable all endpoints
        var baseResponse = new ConfigurationResponse();

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
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com:8443");
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://mtls.example.com:8443/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(8443, result.Value.MtlsEndpointAliases.TokenEndpoint!.Port);
    }

    /// <summary>
    /// Verifies partial explicit configuration works with auto-computation.
    /// </summary>
    [Fact]
    public async Task ConfigurationAsync_WithPartialExplicitAliases_ShouldMixExplicitAndAutoComputed()
    {
        // Arrange
        _oidcOptions.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        _oidcOptions.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions
        {
            TokenEndpoint = new Uri("https://custom1.example.com/token"),
            IntrospectionEndpoint = new Uri("https://custom2.example.com/introspect"),
            // RevocationEndpoint and UserInfoEndpoint will be auto-computed
        };
        var baseResponse = new ConfigurationResponse();

        // Act
        var result = await _formatter.FormatResponseAsync(baseResponse);

        // Assert
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.MtlsEndpointAliases);
        Assert.Equal(new Uri("https://custom1.example.com/token"), result.Value.MtlsEndpointAliases.TokenEndpoint);
        Assert.Equal(new Uri("https://custom2.example.com/introspect"), result.Value.MtlsEndpointAliases.IntrospectionEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/revocation"), result.Value.MtlsEndpointAliases.RevocationEndpoint);
        Assert.Equal(new Uri("https://mtls.example.com/userinfo"), result.Value.MtlsEndpointAliases.UserInfoEndpoint);
    }

    private void SetupEndpointResolver()
    {
        // Setup endpoint resolver to return predictable URIs
        _endpointResolverMock
            .Setup(x => x.Resolve("Token", "Token"))
            .Returns(new Uri("https://example.com/token"));

        _endpointResolverMock
            .Setup(x => x.Resolve("Token", "Revocation"))
            .Returns(new Uri("https://example.com/revocation"));

        _endpointResolverMock
            .Setup(x => x.Resolve("Token", "Introspection"))
            .Returns(new Uri("https://example.com/introspection"));

        _endpointResolverMock
            .Setup(x => x.Resolve("Authentication", "UserInfo"))
            .Returns(new Uri("https://example.com/userinfo"));
    }
}
