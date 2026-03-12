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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="InitialAccessTokenService"/> verifying token issuance
/// per RFC 7591 Section 3.
/// </summary>
[Collection("License")]
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
            .Returns(TestConstants.DefaultIssuer);

        _service = new InitialAccessTokenService(
            _jwtFormatter.Object,
            _issuerProvider.Object);
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldSetCorrectTokenType()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(t => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.NotNull(capturedToken);
        Assert.Equal(JwtTypes.InitialAccessToken, capturedToken.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldSetSubject()
    {
        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(t => capturedToken = t)
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
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(t => capturedToken = t)
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
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .Callback<JsonWebToken>(t => capturedToken = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, expiresIn: null);

        Assert.NotNull(capturedToken);
        Assert.Null(capturedToken.Payload.ExpiresAt);
    }

    [Fact]
    public async Task IssueTokenAsync_ShouldReturnFormattedJwt()
    {
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>()))
            .ReturnsAsync("eyJhbGciOiJSUzI1NiJ9.test.signature");

        var result = await _service.IssueTokenAsync("admin-portal", FixedIssuedAt, TimeSpan.FromHours(1));

        Assert.Equal("eyJhbGciOiJSUzI1NiJ9.test.signature", result);
    }
}
