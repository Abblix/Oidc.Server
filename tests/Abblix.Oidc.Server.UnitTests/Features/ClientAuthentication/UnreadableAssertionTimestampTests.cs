// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The assertion authenticator reads the assertion's timestamps itself, after whatever validator
/// its override chose has run - and that validator may not have looked at them. A timestamp the
/// payload cannot read must then be a refusal here, not an exception out of the token endpoint.
/// </summary>
/// <remarks>
/// The validator is a stub that hands the token back unread, which is the position a host's own
/// override puts this class in when it validates without lifetime handling. The <c>sub</c> read a
/// few lines above already had this protection; the timestamps did not.
/// </remarks>
public class UnreadableAssertionTimestampTests
{
    private const string ClientId = "client_with_an_unreadable_date";
    private static readonly string Issuer = TestConstants.DefaultIssuer.ToString();
    private const string JwtAssertion = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(JwtClaimTypes.ExpiresAt)]
    [InlineData(JwtClaimTypes.IssuedAt)]
    [InlineData(JwtClaimTypes.NotBefore)]
    public async Task AnAssertionWithATimestampOutsideTheRepresentableRange_IsRefused(string claim)
    {
        var (authenticator, replayCache) = Build(payload => payload[claim] = 99999999999999);

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Null(result);

        // Refused before anything irreversible: the identifier of an assertion that could not even
        // be read is not spent.
        replayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// And the same assertion with readable dates authenticates, or the case above would be
    /// satisfied by an authenticator refusing everything.
    /// </summary>
    [Fact]
    public async Task AnAssertionWithReadableTimestamps_Authenticates()
    {
        var (authenticator, _) = Build(_ => { });

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.NotNull(result);
    }

    private static (ClientSecretJwtAuthenticator, Mock<IReplayCache>) Build(Action<JsonObject> corrupt)
    {
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject
            {
                [JwtClaimTypes.Algorithm] = "HS256",
                [JwtClaimTypes.Type] = "JWT",
            }),
            Payload = new JsonWebTokenPayload(new JsonObject
            {
                [JwtClaimTypes.Issuer] = ClientId,
                [JwtClaimTypes.Subject] = ClientId,
                [JwtClaimTypes.JwtId] = "assertion-identifier",
            }),
        };

        token.Payload.IssuedAt = Now;
        token.Payload.ExpiresAt = Now.AddHours(1);
        token.Payload.Audiences = [Issuer];
        corrupt(token.Payload.Json);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
        };

        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(clientInfo);

        // Hands the token back without reading a single claim of it, which is what leaves the
        // timestamps to be met first by the authenticator.
        var tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        tokenValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(
                async (_, parameters) =>
                {
                    if (parameters.ValidateIssuer != null)
                        await parameters.ValidateIssuer(ClientId);

                    return token;
                }));

        var replayCache = new Mock<IReplayCache>(MockBehavior.Strict);
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        var requestInfoProvider = new Mock<IRequestInfoProvider>();
        requestInfoProvider.Setup(p => p.RequestUri).Returns(Issuer);

        var authenticator = new ClientSecretJwtAuthenticator(
            Mock.Of<ILogger<ClientSecretJwtAuthenticator>>(),
            tokenValidator.Object,
            clientInfoProvider.Object,
            requestInfoProvider.Object,
            new FixedClock(Now),
            replayCache.Object,
            Mock.Of<IIssuerProvider>(p => p.GetIssuer() == Issuer),
            Options.Create(new OidcOptions { DefaultSecurityProfile = ClientSecurityProfile.None }));

        return (authenticator, replayCache);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
