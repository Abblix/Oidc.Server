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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SubjectTypeValidator"/> verifying pairwise subject type validation
/// per OpenID Connect Core specification Section 8.
/// </summary>
public class SubjectTypeValidatorTests
{
    private readonly Mock<ISecureHttpFetcher> _secureHttpFetcher;
    private readonly Mock<ILogger<SubjectTypeValidator>> _logger;
    private readonly SubjectTypeValidator _validator;

    public SubjectTypeValidatorTests()
    {
        _secureHttpFetcher = new Mock<ISecureHttpFetcher>(MockBehavior.Strict);
        _logger = new Mock<ILogger<SubjectTypeValidator>>();
        _validator = new SubjectTypeValidator(_secureHttpFetcher.Object, _logger.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        Uri[] redirectUris,
        string? subjectType = SubjectTypes.Public,
        Uri? sectorIdentifierUri = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = redirectUris,
            SubjectType = subjectType,
            SectorIdentifierUri = sectorIdentifierUri
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation skipped for public subject type.
    /// Per OIDC Core, public subject type requires no sector validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPublicSubjectType_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            subjectType: SubjectTypes.Public);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies pairwise with same host succeeds.
    /// Per OIDC Core Section 8.1, pairwise requires consistent sector identifier.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseWithSameHost_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            redirectUris:
            [
                new Uri("https://example.com/callback1"),
                new Uri("https://example.com/callback2")
            ],
            subjectType: SubjectTypes.Pairwise);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal("example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// Verifies error when pairwise with multiple hosts.
    /// Per OIDC Core, pairwise without sector_identifier_uri requires single host.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseWithDifferentHosts_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris:
            [
                new Uri("https://example.com/callback"),
                new Uri("https://other.com/callback")
            ],
            subjectType: SubjectTypes.Pairwise);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, result.Error);
        Assert.Contains("different hosts", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when pairwise redirect URI uses HTTP.
    /// Per OIDC Core, pairwise requires HTTPS for all redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseWithHttpRedirectUri_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("http://example.com/callback")],
            subjectType: SubjectTypes.Pairwise);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("https", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies pairwise with valid sector_identifier_uri succeeds.
    /// Per OIDC Core Section 8.1, sector_identifier_uri allows multiple hosts.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseWithValidSectorIdentifierUri_ShouldReturnNull()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var redirectUris = new[]
        {
            new Uri("https://app1.example.com/callback"),
            new Uri("https://app2.example.com/callback")
        };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(redirectUris));

        var context = CreateContext(
            redirectUris: redirectUris,
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal("example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// Verifies error when sector_identifier_uri is not HTTPS.
    /// Per OIDC Core, sector_identifier_uri must use HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SectorIdentifierUriWithHttp_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: new Uri("http://example.com/sector.json"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("https", result.ErrorDescription);
        Assert.Contains("sector_identifier_uri", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when sector_identifier_uri content has HTTP URIs.
    /// Per OIDC Core, all URIs in sector document must be HTTPS.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SectorContentWithHttpUri_ShouldReturnError()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var sectorContent = new[]
        {
            new Uri("https://example.com/callback"),
            new Uri("http://example.com/callback2") // Invalid HTTP
        };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(sectorContent));

        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("https", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when sector content has extra URIs.
    /// Per OIDC Core, sector document must only contain registered redirect URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SectorContentWithExtraUris_ShouldReturnError()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var sectorContent = new[]
        {
            new Uri("https://example.com/callback"),
            new Uri("https://example.com/extra") // Not in redirect URIs
        };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(sectorContent));

        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("not in the registered list", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when fetching sector_identifier_uri fails.
    /// Per OIDC Core, sector document must be accessible.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SectorUriFetchFails_ShouldReturnError()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var fetchError = new OidcError(ErrorCodes.InvalidRequest, "Failed to fetch");

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Failure(fetchError));

        var context = CreateContext(
            redirectUris: [new Uri(TestConstants.DefaultRedirectUri)],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(fetchError, result);
    }

    /// <summary>
    /// Verifies sector identifier set from single redirect URI host.
    /// Context must be populated with sector identifier for pairwise processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseSingleUri_ShouldSetSectorIdentifier()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://app.example.com/callback")],
            subjectType: SubjectTypes.Pairwise);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal("app.example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// Verifies sector identifier set from sector_identifier_uri host.
    /// Per OIDC Core, sector identifier is derived from sector_identifier_uri host.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSectorUri_ShouldSetSectorIdentifierFromUriHost()
    {
        // Arrange
        var sectorUri = new Uri("https://sector.example.com/sector.json");
        var redirectUris = new[] { new Uri("https://app.example.com/callback") };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(redirectUris));

        var context = CreateContext(
            redirectUris: redirectUris,
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal("sector.example.com", context.SectorIdentifier);
    }
}
