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
    /// A pairwise client that registered no redirect URI, no sector identifier URI and no backchannel
    /// delivery mode is refused, not crashed on.
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
        Uri? sectorIdentifierUri = null,
        string? deliveryMode = null,
        Uri? notificationEndpoint = null,
        Uri? jwksUri = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = redirectUris,
            SubjectType = subjectType,
            SectorIdentifierUri = sectorIdentifierUri,
            BackChannelTokenDeliveryMode = deliveryMode,
            BackChannelClientNotificationEndpoint = notificationEndpoint,
            JwksUri = jwksUri
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
    /// A CIBA client's sector document must list the URI its delivery mode uses in place of the
    /// redirect URI, and each mode names a different one.
    /// </summary>
    /// <remarks>
    /// CIBA Core 1.0 Section 4: "In CIBA Poll and Ping modes the jwks_uri is used in place of the
    /// redirect_uri. In CIBA Push mode the backchannel_client_notification_endpoint is used in place
    /// of the redirect_uri", and the document "can contain jwks_uris and
    /// backchannel_client_notification_endpoints as well as redirect_uri". The membership check is
    /// what stops a client claiming a sector it does not belong to, so an unchecked URI is a client
    /// receiving identifiers computed from somebody else's host.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Push, true, false)]
    [InlineData(BackchannelTokenDeliveryModes.Push, false, true)]
    [InlineData(BackchannelTokenDeliveryModes.Poll, true, false)]
    [InlineData(BackchannelTokenDeliveryModes.Poll, false, true)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, true, false)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, false, true)]
    public async Task ValidateAsync_CibaSectorDocument_MustListTheUriTheModeNames(
        string deliveryMode, bool listedInDocument, bool expectError)
    {
        // Arrange
        var sectorUri = new Uri("https://sector.example.com/sector.json");
        var modeUri = new Uri($"https://client.example.com/{deliveryMode}");

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success(
                listedInDocument ? [modeUri] : [new Uri("https://client.example.com/something-else")]));

        var isPush = deliveryMode == BackchannelTokenDeliveryModes.Push;
        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri,
            deliveryMode: deliveryMode,
            notificationEndpoint: isPush ? modeUri : null,
            jwksUri: isPush ? null : modeUri);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        if (expectError)
        {
            Assert.NotNull(result);
            Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        }
        else
        {
            Assert.Null(result);
            Assert.Equal("sector.example.com", context.SectorIdentifier);
        }
    }

    /// <summary>
    /// A registration with no delivery mode is not asked for either CIBA URI, even when it has them.
    /// </summary>
    /// <remarks>
    /// The requirement is written per mode, so making it unconditional would refuse a plain pairwise
    /// client that happens to publish a jwks_uri - which OIDC Core has never required to be listed.
    /// This row is what stops the two arms above from widening into every registration.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_PairwiseWithNoDeliveryMode_DoesNotRequireTheCibaUris()
    {
        // Arrange
        var sectorUri = new Uri("https://sector.example.com/sector.json");
        var redirectUri = new Uri("https://client.example.com/callback");

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success([redirectUri]));

        var context = CreateContext(
            redirectUris: [redirectUri],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri,
            deliveryMode: null,
            notificationEndpoint: new Uri("https://client.example.com/notify"),
            jwksUri: new Uri("https://client.example.com/jwks"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal("sector.example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// The refusal names the URI that was missing, rather than calling everything a redirect URI.
    /// </summary>
    /// <remarks>
    /// A message saying "redirect URIs" to a client whose notification endpoint was the omission sends
    /// its author to the wrong piece of metadata, and the sector document is edited by a person.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_MissingNotificationEndpoint_NamesItInTheMessage()
    {
        // Arrange
        var sectorUri = new Uri("https://sector.example.com/sector.json");
        var notificationEndpoint = new Uri("https://client.example.com/notify");

        _secureHttpFetcher
            .Setup(f => f.FetchAsync<Uri[]>(sectorUri))
            .ReturnsAsync(Result<Uri[], OidcError>.Success([]));

        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            sectorIdentifierUri: sectorUri,
            deliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: notificationEndpoint);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains(notificationEndpoint.OriginalString, result.ErrorDescription);
    }
    /// <summary>
    /// With no sector identifier URI and no redirect URI, the sector is the host of the URI the
    /// delivery mode names.
    /// </summary>
    /// <remarks>
    /// CIBA Core 1.0 Section 4: the jwks_uri stands in for the redirect URI in poll and ping, the
    /// backchannel_client_notification_endpoint in push. Ping registers a notification endpoint as
    /// well and its sector is still the jwks_uri, which is why ping is grouped with poll here and not
    /// with push - a row that exists to catch the grouping being done by "has a notification endpoint"
    /// instead of by mode.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Push, "notify.example.com")]
    [InlineData(BackchannelTokenDeliveryModes.Poll, "keys.example.com")]
    [InlineData(BackchannelTokenDeliveryModes.Ping, "keys.example.com")]
    public async Task ValidateAsync_CibaWithNoRedirectUri_TakesTheSectorFromTheModesUri(
        string deliveryMode, string expectedSector)
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            deliveryMode: deliveryMode,
            notificationEndpoint: new Uri("https://notify.example.com/callback"),
            jwksUri: new Uri("https://keys.example.com/jwks"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(expectedSector, context.SectorIdentifier);
    }

    /// <summary>
    /// A pairwise poll or ping client with no sector identifier URI, no redirect URI and no
    /// jwks_uri is refused.
    /// </summary>
    /// <remarks>
    /// All three absences are load-bearing, and the name says so because the narrower reading is
    /// what this row actually holds. CIBA Core 1.0 Section 4 asks for more than this - "it MUST
    /// check if a valid jwks_uri is set when the subject_type is pairwise" is unconditional, so a
    /// poll client that registered a redirect URI and no jwks_uri is accepted here and should not
    /// be. That gap is not this change's to close and is recorded rather than implied by a row
    /// whose name promises it.
    /// <para>
    /// What this row does hold: with none of the three, there is no host to derive a sector from,
    /// and falling back to the client id would make the identifiers per-client where the
    /// specification makes them per-sector.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Poll)]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    public async Task ValidateAsync_PairwisePollOrPingWithNoUriAtAll_ShouldReturnError(string deliveryMode)
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            deliveryMode: deliveryMode,
            notificationEndpoint: new Uri("https://notify.example.com/callback"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// A registered redirect URI still decides the sector, even for a client that also registered a
    /// backchannel delivery mode.
    /// </summary>
    /// <remarks>
    /// The order matters beyond correctness: the pairwise pseudonym is sealed with the sector as
    /// associated data, so moving a client's sector invalidates every identifier already issued to it.
    /// Putting the CIBA URIs BELOW the redirect URI is what keeps every client that has one where it
    /// was.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_CibaClientWithARedirectUri_KeepsTheRedirectUriHost()
    {
        // Arrange
        var context = CreateContext(
            redirectUris: [new Uri("https://app.example.com/callback")],
            subjectType: SubjectTypes.Pairwise,
            deliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: new Uri("https://notify.example.com/callback"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal("app.example.com", context.SectorIdentifier);
    }

    /// <summary>
    /// The URI a sector is taken from must be https, the same rule the redirect URI branch applies.
    /// </summary>
    /// <remarks>
    /// Push is the weaker case and poll is the one that matters: for the notification endpoint
    /// BackChannelAuthenticationValidator enforces the specification's "It MUST be an HTTPS URL"
    /// as well, just later in the pipeline, whereas for the jwks_uri NOTHING else in the
    /// registration pipeline checks the scheme at all. Both are driven, so that a reader who
    /// reorders the validators cannot delete this check on the strength of the duplicate.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    [InlineData(BackchannelTokenDeliveryModes.Poll)]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    public async Task ValidateAsync_CibaSectorUriOverHttp_ShouldReturnError(string deliveryMode)
    {
        // Arrange
        var overHttp = new Uri("http://client.example.com/callback");
        var isPush = deliveryMode == BackchannelTokenDeliveryModes.Push;
        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            deliveryMode: deliveryMode,
            notificationEndpoint: isPush ? overHttp : null,
            jwksUri: isPush ? null : overHttp);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Null(context.SectorIdentifier);
    }
    /// <summary>
    /// A relative URI where the sector's host would come from is refused, not dereferenced.
    /// </summary>
    /// <remarks>
    /// A registration body is attacker-shaped JSON, and <c>[AbsoluteUri]</c> does not reach it: the
    /// attribute is honoured by the form binder rather than by the JSON deserializer, so "/jwks"
    /// arrives intact. Every <see cref="Uri"/> member this branch then reads - Scheme, Host - throws
    /// <see cref="InvalidOperationException"/> on a relative value rather than returning anything, so
    /// what the client meets is a fault instead of the refusal it should be. The redirect-URI branch
    /// never had this exposure: it only ever sees values that survived
    /// <c>RedirectUrisValidator</c>.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    [InlineData(BackchannelTokenDeliveryModes.Poll)]
    public async Task ValidateAsync_RelativeCibaSectorUri_IsRefusedRatherThanDereferenced(string deliveryMode)
    {
        // Arrange
        var relative = new Uri("/jwks", UriKind.Relative);
        var isPush = deliveryMode == BackchannelTokenDeliveryModes.Push;
        var context = CreateContext(
            redirectUris: [],
            subjectType: SubjectTypes.Pairwise,
            deliveryMode: deliveryMode,
            notificationEndpoint: isPush ? relative : null,
            jwksUri: isPush ? null : relative);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Null(context.SectorIdentifier);
    }
}
