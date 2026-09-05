// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationValidator"/> verifying
/// CIBA (Client-Initiated Backchannel Authentication) configuration validation.
/// </summary>
public class BackChannelAuthenticationValidatorTests
{
    private readonly Mock<IJsonWebTokenValidator> _jwtValidator;
    private readonly BackChannelAuthenticationValidator _validator;

    public BackChannelAuthenticationValidatorTests()
    {
        _jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _validator = new BackChannelAuthenticationValidator(_jwtValidator.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? tokenDeliveryMode = null,
        Uri? notificationEndpoint = null,
        string? signingAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            BackChannelTokenDeliveryMode = tokenDeliveryMode,
            BackChannelClientNotificationEndpoint = notificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = signingAlg
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when no CIBA configuration specified.
    /// Per OIDC CIBA, backchannel authentication is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoBackChannelConfig_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with poll mode without notification endpoint.
    /// Per OIDC CIBA, poll mode does not require notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PollModeWithoutEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when poll mode specifies notification endpoint.
    /// Per OIDC CIBA, poll mode must not have notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PollModeWithEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies error when ping mode lacks notification endpoint.
    /// Per OIDC CIBA, ping mode requires notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithoutEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Ping);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with ping mode and a notification endpoint.
    /// Per CIBA Core 1.0 Section 4, backchannel_client_notification_endpoint is "REQUIRED if the token
    /// delivery mode is set to ping or push".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Ping,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when the notification endpoint is not an HTTPS URL.
    /// CIBA Core 1.0 Section 4, on the registration metadata: "It MUST be an HTTPS URL." The TLS clause
    /// that usually travels with it is Section 9 and is not a property of the registered value, so
    /// nothing here can check it.
    /// </summary>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    public async Task ValidateAsync_NotificationEndpointNotHttps_ShouldReturnError(string deliveryMode)
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: deliveryMode,
            notificationEndpoint: new Uri("http://client.example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies error when push mode lacks notification endpoint.
    /// Per OIDC CIBA, push mode requires notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushModeWithoutEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Push);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with push mode and a notification endpoint.
    /// Per CIBA Core 1.0 Section 4, backchannel_client_notification_endpoint is "REQUIRED if the token
    /// delivery mode is set to ping or push".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushModeWithEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error with unsupported token delivery mode.
    /// Per OIDC CIBA, only poll, ping, and push are standard modes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedDeliveryMode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: "custom-mode");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with supported signing algorithm.
    /// Per OIDC CIBA, signing algorithm must be from supported set.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedSigningAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when signing algorithm not supported.
    /// Per OIDC CIBA, only advertised algorithms are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedSigningAlg_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: SigningAlgorithms.ES512);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds when signing algorithm not specified.
    /// Per OIDC CIBA, signing algorithm is optional.
    /// </summary>
    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("SonarAnalyzer", "S4144",
        Justification = "Separate CIBA scenarios that happen to share identical setup; names document distinct spec requirements.")]
    public async Task ValidateAsync_WithoutSigningAlg_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies algorithm comparison is case-sensitive.
    /// Per JOSE, algorithm names are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SigningAlgCaseSensitive_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns(["RS256"]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: "rs256"); // Different case

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Verifies validation with empty string signing algorithm.
    /// Empty string should be treated as no value (not validated).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptySigningAlg_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// A relative notification endpoint is refused, not faulted on.
    /// </summary>
    /// <remarks>
    /// One instance of a class that arrives at every validator reading a URI member: <see cref="Uri.Scheme"/>
    /// raises on a relative URI rather than returning anything, so a scheme comparison alone turns a
    /// registration that should be refused into a server fault. <c>[AbsoluteUri]</c> sits on the member
    /// and does not help - the form binder honours it and the JSON deserializer does not - which is why
    /// each site states absoluteness itself rather than relying on the model.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    public async Task ValidateAsync_ARelativeNotificationEndpoint_IsRefusedRatherThanFaulting(string mode)
    {
        var context = CreateContext(mode, new Uri("/cb", UriKind.Relative));

        var result = await _validator.ValidateAsync(context);

        // The same code the relative case gets from StoredUriValidator ahead of this one in the
        // pipeline. Every refusal this validator writes carries it, which is what makes the member
        // answer with one code however it is wrong - changing only the scheme refusal left the poll
        // and ping ones, about the same member, still saying invalid_request.
        Assert.Equal(ErrorCodes.InvalidClientMetadata, Assert.IsType<OidcError>(result).Error);
    }

    /// <summary>
    /// Each refusal this validator writes says which thing was wrong, and says it in its own words.
    /// </summary>
    /// <remarks>
    /// Every other row here reads <c>result.Error</c>, and all five refusals carry a registration error
    /// code, so the code cannot tell them apart. Measured before this row existed: SWAPPING the poll and
    /// ping-or-push messages between their arms - so a client is told an endpoint is required when it
    /// registered one too many - left 2996 unit rows and 219 E2E rows green. The description is the only
    /// thing an integrator reads, and it was the only thing nothing read.
    /// <para>
    /// A distinctive FRAGMENT rather than the whole sentence, so rewording a refusal does not fail a row
    /// that is not about the wording. What each fragment has to do is separate its arm from the other
    /// four, which is exactly what the swap defeated.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Poll, "https://client.example/cb", null, "is invalid if")]
    [InlineData(BackchannelTokenDeliveryModes.Ping, null, null, "is required if")]
    [InlineData(BackchannelTokenDeliveryModes.Push, null, null, "is required if")]
    [InlineData("carrier-pigeon", null, null, "delivery mode is not supported")]
    // The ORDER, which nothing held. These TWO rows are the whole of it: the orderings differ only
    // where the scheme check would fire AND an arm would fire, which is poll with a bad endpoint
    // and an unsupported mode with a bad endpoint. The ping-or-push arm requires a null endpoint,
    // so the scheme check can never fire beside it, and the algorithm check sits below both either
    // way. With the scheme check moved back above the arms, exactly these two read "HTTPS scheme"
    // instead and nothing else in any suite moves.
    //
    // A client wrong about its MODE has two things wrong with it, and which one it is told about is
    // the whole point of where the check sits.
    [InlineData("carrier-pigeon", "http://client.example/cb", null, "delivery mode is not supported")]
    [InlineData(BackchannelTokenDeliveryModes.Poll, "http://client.example/cb", null, "is invalid if")]
    [InlineData(BackchannelTokenDeliveryModes.Ping, "http://client.example/cb", null, "HTTPS scheme")]
    [InlineData(BackchannelTokenDeliveryModes.Poll, null, "NOPE", "signing algorithm is not supported")]
    public async Task ValidateAsync_EachRefusal_SaysWhichThingIsWrong(
        string mode, string? endpoint, string? signingAlg, string fragment)
    {
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(
            mode,
            endpoint is null ? null : new Uri(endpoint, UriKind.Absolute),
            signingAlg);

        var result = Assert.IsType<OidcError>(await _validator.ValidateAsync(context));

        Assert.Contains(fragment, result.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// A plain-HTTP notification endpoint is refused as registration metadata, like the relative one.
    /// </summary>
    /// <remarks>
    /// The same member used to answer with two codes depending on HOW it was wrong: relative got
    /// <c>invalid_client_metadata</c> from the URI validator ahead of this one, plain HTTP got
    /// <c>invalid_request</c> from here. An integrator reading the two concluded that two different
    /// kinds of thing had gone wrong with one field.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_APlainHttpNotificationEndpoint_IsRefusedAsRegistrationMetadata()
    {
        var context = CreateContext(
            BackchannelTokenDeliveryModes.Ping,
            new Uri("http://client.example/cb", UriKind.Absolute));

        var result = Assert.IsType<OidcError>(await _validator.ValidateAsync(context));

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// A registration naming no delivery mode is not told its mode is unsupported.
    /// </summary>
    /// <remarks>
    /// The null-mode exit moved BELOW the switch so the endpoint check could see a registration that
    /// names no mode. That put null in reach of the unsupported-mode arm, which asks for a mode that is
    /// "not poll, ping or push" - and null qualifies. The arm carries an explicit "not null", and
    /// removing it turns seventeen unit rows red across two files and sixty-four E2E rows across two
    /// SUITES - the MinimalApi one carries eleven of them. The number has been wrong twice for two
    /// different reasons: it once counted only the suites that happened to be open, and it said
    /// sixteen until the row below was added, which fails under the same plant. A count is valid for
    /// the state it measured, and an edit in the same commit can invalidate it. This row is the one
    /// that says WHY in a sentence, rather than the only one that speaks.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_NoDeliveryModeAtAll_IsNotAnUnsupportedMode()
    {
        var context = CreateContext(notificationEndpoint: new Uri("https://client.example/cb"));

        Assert.Null(await _validator.ValidateAsync(context));
    }

    /// <summary>
    /// A registration naming no delivery mode is not judged on its CIBA signing algorithm either.
    /// </summary>
    /// <remarks>
    /// The row above pins where the null-mode exit sits relative to the switch. This one pins the other
    /// side of it - the algorithm check below - and without it that position was free: moving the exit
    /// beneath the algorithm check left every suite green. A boundary a value can cross in either
    /// direction needs a row on each side, and the exit had one.
    /// <para>
    /// What it pins is that the algorithm check is NOT REACHED, which is stronger than what it looks
    /// like it asserts: the mock is strict and has no SigningAlgorithmsSupported setup, so the moved
    /// exit fails this row by throwing rather than by returning a refusal. Reaching the check at all
    /// is the thing being refused.
    /// </para>
    /// <para>
    /// And the difference is not whether the REGISTRATION is refused - SigningAlgorithmsValidator runs
    /// immediately after this one and judges the algorithm for every mode, so the endpoint refuses it
    /// either way. What moves is which validator answers, and therefore the code and the words the
    /// client is given.
    /// </para>
    /// <para>
    /// Silent rather than refusing here because the parameter is CIBA's own, and a registration that
    /// asks for no CIBA is not asking for this algorithm.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_NoDeliveryMode_IsNotJudgedOnItsCibaSigningAlgorithm()
    {
        var context = CreateContext(signingAlg: "NOPE");

        Assert.Null(await _validator.ValidateAsync(context));
    }
}
