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
/// Covers what a registration access token carries. RFC 7592 Section 3 has the client present it back to this
/// server to manage its own registration, so the two questions it must answer are who reads it and which
/// registration it is about - and those are different claims.
/// </summary>
public class RegistrationAccessTokenServiceTests
{
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private static readonly DateTimeOffset IssuedAt = new(2026, 3, 12, 10, 0, 0, TimeSpan.Zero);
    private const string ClientId = "managed-client";
    private const string TokenId = "jti-1";

    private readonly Mock<IAuthServiceJwtFormatter> _jwtFormatter;
    private readonly RegistrationAccessTokenService _service;

    public RegistrationAccessTokenServiceTests()
    {
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        _jwtFormatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);

        _service = new RegistrationAccessTokenService(
            _jwtFormatter.Object,
            issuerProvider.Object,
            Options.Create(new OidcOptions()));
    }

    private async Task<JsonWebToken> IssueAsync()
    {
        JsonWebToken? captured = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((t, _) => captured = t)
            .ReturnsAsync("formatted-jwt");

        await _service.IssueTokenAsync(ClientId, IssuedAt, TimeSpan.FromDays(30), TokenId);

        Assert.NotNull(captured);
        return captured!;
    }

    /// <summary>
    /// The audience names this server, because this server is what reads the token: the client presents it to
    /// the registration endpoint and never opens it. That is the same answer every other token issued here for
    /// its own consumption gives.
    /// </summary>
    [Fact]
    public async Task IssueToken_ShouldSetAudienceToIssuer()
    {
        var token = await IssueAsync();

        Assert.Equal([Issuer], token.Payload.Audiences.ToArray());
    }

    /// <summary>
    /// Which registration the token is about is a separate question, and the subject is what answers it. That
    /// is the claim the validator binds against, so a token cannot manage a registration other than its own.
    /// </summary>
    [Fact]
    public async Task IssueToken_ShouldNameTheManagedClientInTheSubject()
    {
        var token = await IssueAsync();

        Assert.Equal(ClientId, token.Payload.Subject);
        Assert.Equal(Issuer, token.Payload.Issuer);
        Assert.Equal(JwtTypes.RegistrationAccessToken, token.Header.Type);
        Assert.Equal(TokenId, token.Payload.JwtId);
    }
}
