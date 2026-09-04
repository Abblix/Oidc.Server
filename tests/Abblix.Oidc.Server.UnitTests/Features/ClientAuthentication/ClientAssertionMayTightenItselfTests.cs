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
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// A client assertion is validated before anyone knows whose it is: the client is identified from
/// the assertion itself, so the clock tolerance applied while validating it can only be the
/// deployment's. A client asking to be held to a tighter profile could not be heard on this path.
/// </summary>
/// <remarks>
/// The answer is a second pass once the client is known. These cases are about that pass: every
/// assertion here carries the identifier and the expiry the specification demands and names the
/// issuer as its audience, so the only thing separating acceptance from refusal is which profile the
/// client names for itself.
/// </remarks>
public class ClientAssertionMayTightenItselfTests
{
    private const string ClientId = "tightening_client";
    private static readonly string Issuer = TestConstants.DefaultIssuer.ToString();
    private const string JwtAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Dated ahead of every profile this server carries, and inside the window a deployment holding
    /// clients to nothing grants.
    /// </summary>
    private static readonly TimeSpan AheadOfEveryProfileButNone = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The case this exists for: a client naming FAPI 2.0 under a deployment naming nothing is held
    /// to the seconds section 5.3.2.1 grants, not to the minutes the deployment would. Before the
    /// second pass this assertion authenticated the client.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_IsHeldToItUnderADeploymentNamingNothing()
    {
        var (authenticator, replayCache) = CreateAuthenticator();

        var result = await Authenticate(
            authenticator,
            ClientSecurityProfile.Fapi2,
            Now + AheadOfEveryProfileButNone);

        Assert.Null(result);

        // The refusal lands before the identifier is reserved: a reservation is spent and cannot be
        // given back, so burning it on an assertion this pass rejects would refuse the client's next
        // attempt with the same identifier for the wrong reason.
        replayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// And the same assertion from a client naming nothing authenticates, without which the case
    /// above would be satisfied by a pass refusing every assertion dated ahead at all.
    /// </summary>
    [Fact]
    public async Task AClientNamingNothing_KeepsTheDeploymentsWindow()
    {
        var (authenticator, _) = CreateAuthenticator();

        var result = await Authenticate(
            authenticator,
            clientProfile: null,
            issuedAt: Now + AheadOfEveryProfileButNone);

        Assert.NotNull(result);
    }

    /// <summary>
    /// And an assertion inside the tighter window authenticates the FAPI client too, or the case
    /// above would be satisfied by a pass refusing every assertion from a client naming a profile.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_KeepsAnAssertionInsideItsOwnWindow()
    {
        var (authenticator, _) = CreateAuthenticator();

        var result = await Authenticate(
            authenticator,
            ClientSecurityProfile.Fapi2,
            Now.AddSeconds(5));

        Assert.NotNull(result);
    }

    private readonly Mock<IClientJwtValidator> validator = new(MockBehavior.Strict);

    private async Task<ClientInfo?> Authenticate(
        PrivateKeyJwtAuthenticator authenticator,
        ClientSecurityProfile? clientProfile,
        DateTimeOffset issuedAt)
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = clientProfile,
        };

        validator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(CreateAssertion(issuedAt), clientInfo));

        return await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });
    }

    private static JsonWebToken CreateAssertion(DateTimeOffset issuedAt)
    {
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject
            {
                [JwtClaimTypes.Algorithm] = "RS256",
                [JwtClaimTypes.Type] = "JWT",
            }),
            Payload = new JsonWebTokenPayload(new JsonObject
            {
                [JwtClaimTypes.Issuer] = ClientId,
                [JwtClaimTypes.Subject] = ClientId,
                [JwtClaimTypes.JwtId] = "assertion-identifier",
            }),
        };

        token.Payload.IssuedAt = issuedAt;
        token.Payload.ExpiresAt = Now.AddHours(1);
        token.Payload.Audiences = [Issuer];
        return token;
    }

    private (PrivateKeyJwtAuthenticator, Mock<IReplayCache>) CreateAuthenticator()
    {
        var replayCache = new Mock<IReplayCache>(MockBehavior.Strict);
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        var services = new ServiceCollection();
        services.AddScoped(_ => validator.Object);

        var authenticator = new PrivateKeyJwtAuthenticator(
            Mock.Of<ILogger<PrivateKeyJwtAuthenticator>>(),
            replayCache.Object,
            services.BuildServiceProvider(),
            Mock.Of<IIssuerProvider>(p => p.GetIssuer() == Issuer),
            Options.Create(new OidcOptions { DefaultSecurityProfile = ClientSecurityProfile.None }),
            new FixedClock(Now));

        return (authenticator, replayCache);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
