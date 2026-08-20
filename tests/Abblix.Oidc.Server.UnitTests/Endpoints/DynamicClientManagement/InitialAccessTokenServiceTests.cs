// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="InitialAccessTokenService"/> verifying token issuance
/// per RFC 7591 Section 3.
/// </summary>
public class InitialAccessTokenServiceTests
{
    private static readonly DateTimeOffset FixedIssuedAt = new(2026, 3, 12, 10, 0, 0, TimeSpan.Zero);

    private readonly Mock<IAuthServiceJwtFormatter> _jwtFormatter;
    private readonly Mock<IIssuerProvider> _issuerProvider;
    private readonly InitialAccessTokenService _service;

    public InitialAccessTokenServiceTests()
    {
        _jwtFormatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);
        _issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(TestConstants.DefaultIssuer.OriginalString);

        _service = new InitialAccessTokenService(
            _jwtFormatter.Object,
            _issuerProvider.Object,
            Options.Create(new OidcOptions()));
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldSetCorrectTokenType()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.NotNull(capturedToken);
        Assert.Equal(JwtTypes.InitialAccessToken, capturedToken.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    /// <summary>
    /// RFC 7591 Section 3 has this token authorize a registration call at this server, so this server is what
    /// consumes it - and the audience is where a token says so. Without it this would be the only token issued
    /// here whose intended recipient is unstated, and the only one whose audience could not be checked.
    /// </summary>
    [Fact]
    public async Task IssueTokenAsync_ShouldSetAudienceToIssuer()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.NotNull(capturedToken);
        Assert.Equal(
            [TestConstants.DefaultIssuer.OriginalString],
            capturedToken.Payload.Audiences.ToArray());
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldSetSubject()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.NotNull(capturedToken);
        Assert.Equal("admin-portal", capturedToken.Payload.Subject);
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldSetExpirationFromIssuedAtPlusExpiresIn()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        var expiresIn = TimeSpan.FromDays(30);

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, expiresIn);

        Assert.NotNull(capturedToken);
        Assert.Equal(FixedIssuedAt, capturedToken.Payload.IssuedAt);
        Assert.Equal(FixedIssuedAt, capturedToken.Payload.NotBefore);
        Assert.Equal(FixedIssuedAt + expiresIn, capturedToken.Payload.ExpiresAt);
    }

    [Fact]
    public async Task IssueTokenAsync_WithNullExpiresIn_ShouldSetNullExpiration()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, expiresIn: null);

        Assert.NotNull(capturedToken);
        Assert.Null(capturedToken.Payload.ExpiresAt);
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldReturnFormattedJwt()
    {
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync("eyJhbGciOiJSUzI1NiJ9.test.signature");

        var result = await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.Equal("eyJhbGciOiJSUzI1NiJ9.test.signature", result);
    }
}
