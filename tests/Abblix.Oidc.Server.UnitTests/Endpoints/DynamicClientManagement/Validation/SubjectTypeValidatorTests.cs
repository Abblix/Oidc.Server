// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        _validator = new SubjectTypeValidator(_logger.Object, _secureHttpFetcher.Object);
    }

    /// <summary>
    /// A pairwise client that registered no redirect URI and no sector identifier URI is refused, not
    /// crashed on.
    /// </summary>
    /// <remarks>
    /// The sibling of the redirect URI validator's own null case, and reachable for the same reason from
    /// the opposite direction: a client asking only for a grant type that needs no redirection registers
    /// none, which that validator correctly permits, so this one receives an absent or empty list. It then
    /// took the first host out of a list that has none. Both shapes are covered because they arrive by
    /// different routes - the member omitted or sent as null, and the member sent as an empty array.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_WithPairwiseAndNoRedirectUris_ShouldReturnError(bool nullRatherThanEmpty)
    {
        var context = CreateContext(nullRatherThanEmpty ? null! : [], SubjectTypes.Pairwise);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
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
            redirectUris: [TestConstants.DefaultRedirectUri],
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
                TestConstants.DefaultRedirectUri,
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
            redirectUris: [TestConstants.DefaultRedirectUri],
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
            TestConstants.DefaultRedirectUri,
            new Uri("http://example.com/callback2") // Invalid HTTP
        };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(sectorContent));

        var context = CreateContext(
            redirectUris: [TestConstants.DefaultRedirectUri],
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
    /// Verifies a shared sector document listing URIs of other clients is accepted.
    /// Per OIDC Core Section 8.1, the document may be shared across several clients of the same
    /// sector - only the registered redirect URIs must be present in it, extra entries are fine.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SectorContentWithExtraUris_ShouldReturnNull()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var sectorContent = new[]
        {
            TestConstants.DefaultRedirectUri,
            new Uri("https://example.com/another-clients-callback") // Belongs to a sibling client
        };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(sectorContent));

        var context = CreateContext(
            redirectUris: [TestConstants.DefaultRedirectUri],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal("example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// Verifies error when a registered redirect URI is absent from the sector document.
    /// Per OIDC Core Section 8.1, all registered redirect URIs must be included in the document -
    /// otherwise a client could claim a sector it does not belong to.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RegisteredUriMissingFromSectorContent_ShouldReturnError()
    {
        // Arrange
        var sectorUri = new Uri("https://example.com/sector.json");
        var sectorContent = new[] { new Uri("https://example.com/listed-callback") };

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(sectorContent));

        var context = CreateContext(
            redirectUris: [TestConstants.DefaultRedirectUri], // Not listed in the sector document
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
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
            redirectUris: [TestConstants.DefaultRedirectUri],
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
    /// <summary>
    /// A relative URI where a sector host would come from is refused, not dereferenced.
    /// </summary>
    /// <remarks>
    /// <see cref="Uri.Scheme"/> throws on a relative URI rather than returning anything, so a scheme
    /// comparison alone turns a registration that should be refused into a server fault. Nothing upstream
    /// can be relied on to have looked: <c>RedirectUrisValidator</c> enters its absoluteness loop only for
    /// the grant types that cannot answer without a redirect URI, so a CIBA-only registration walks past
    /// it, and <c>[AbsoluteUri]</c> is honoured by the form binder rather than by the JSON deserializer.
    /// <para>
    /// The sector identifier document is the second arm and the sharper one: its entries come from an
    /// address the client chose, so they are third-party JSON reaching the same expression.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_ARelativeRedirectUri_IsRefusedRatherThanFaulting()
    {
        var context = CreateContext(
            redirectUris: [new Uri("/cb", UriKind.Relative)],
            subjectType: SubjectTypes.Pairwise);

        var result = await _validator.ValidateAsync(context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, Assert.IsType<OidcError>(result).Error);
        Assert.Null(context.SectorIdentifier);
    }

    /// <summary>
    /// The control: an absolute https redirect URI still yields its host as the sector.
    /// </summary>
    /// <remarks>
    /// Without it a validator that refused every redirect URI would pass the row above, and every
    /// pairwise web client would stop registering.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_AnAbsoluteHttpsRedirectUri_StillGivesItsHost()
    {
        var context = CreateContext(
            redirectUris: [new Uri("https://app.example.com/cb")],
            subjectType: SubjectTypes.Pairwise);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Equal("app.example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// A relative URI in the FETCHED sector identifier document is refused for BEING relative, not for
    /// something else that happens to answer the same code.
    /// </summary>
    /// <remarks>
    /// The first version of this row served a document containing only the relative entry, so the subset
    /// check refused it for not listing the registered redirect URI - the same error code, from a
    /// different arm. Deleting the scheme check outright left the row green. The registered URI is in the
    /// document now, so the subset check passes and only the scheme arm can answer, and the message is
    /// asserted rather than the code.
    /// <para>
    /// The sharper of the two arms: those entries come from a document at an address the client chose,
    /// so they are third-party JSON arriving at the expression that throws on a relative value.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_ARelativeUriInTheSectorDocument_IsRefusedRatherThanFaulting()
    {
        var sectorUri = new Uri("https://sector.example.com/uris.json");
        var registered = new Uri("https://app.example.com/cb");
        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(new[] { registered, new Uri("/cb", UriKind.Relative) });

        var context = CreateContext(
            redirectUris: [registered],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        var result = await _validator.ValidateAsync(context);

        var error = Assert.IsType<OidcError>(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains("sector identifier document", error.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control: a document whose entries are all absolute https URIs still registers.
    /// </summary>
    /// <remarks>
    /// Without it, an arm refusing every document would pass the row above and no pairwise client with a
    /// sector identifier URI could register at all.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_ASectorDocumentOfAbsoluteHttpsUris_Registers()
    {
        var sectorUri = new Uri("https://sector.example.com/uris.json");
        var registered = new Uri("https://app.example.com/cb");
        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(new[] { registered });

        var context = CreateContext(
            redirectUris: [registered],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Equal("sector.example.com", context.SectorIdentifier);
    }
}
