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
/// A client assertion is validated before anyone knows whose it is: the client is identified from
/// the assertion itself, so the clock tolerance applied while validating it can only be the
/// deployment's. A client asking to be held to a tighter profile could not be heard on this path.
/// </summary>
/// <remarks>
/// The subject is <see cref="ClientSecretJwtAuthenticator"/> rather than its sibling, because this is
/// where the base class's second pass is the ONLY one: it validates through
/// <see cref="IJsonWebTokenValidator"/> directly, while <see cref="PrivateKeyJwtAuthenticator"/> goes
/// through the client JWT validator, which now performs the same check itself.
///
/// Every assertion here carries the identifier and the expiry the specification demands and names the
/// issuer as its audience, so the only thing separating acceptance from refusal is which profile the
/// client names for itself.
/// </remarks>
public class ClientAssertionMayTightenItselfTests
{
    private const string ClientId = "tightening_client";
    private static readonly string Issuer = TestConstants.DefaultIssuer.ToString();
    private const string JwtAssertion = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Beyond every profile this server carries, and inside the window a deployment holding clients
    /// to nothing grants.
    /// </summary>
    private static readonly TimeSpan BeyondEveryProfileButNone = TimeSpan.FromMinutes(1);

    private readonly Mock<IJsonWebTokenValidator> tokenValidator = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> clientInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<IReplayCache> replayCache = new(MockBehavior.Strict);

    /// <summary>
    /// The case this exists for: a client naming FAPI 2.0 under a deployment naming nothing is held
    /// to the seconds section 5.3.2.1 grants, not to the minutes the deployment would. Before the
    /// second pass this assertion authenticated the client.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_IsHeldToItsOwnForwardWindow()
    {
        var result = await Authenticate(
            ClientSecurityProfile.Fapi2,
            issuedAt: Now + BeyondEveryProfileButNone);

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
    public async Task AClientNamingNothing_KeepsTheDeploymentsForwardWindow()
    {
        var result = await Authenticate(
            clientProfile: null,
            issuedAt: Now + BeyondEveryProfileButNone);

        Assert.NotNull(result);
    }

    /// <summary>
    /// The backward half, which is the larger of the two shifts: FAPI 2.0 grants a token no life at
    /// all past the expiry its issuer chose, where a deployment naming nothing grants minutes.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_IsHeldToItsOwnExpiry()
    {
        var result = await Authenticate(
            ClientSecurityProfile.Fapi2,
            expiresAt: Now.AddSeconds(-1));

        Assert.Null(result);
    }

    /// <summary>
    /// And the same expired assertion from a client naming nothing authenticates, which is what
    /// makes the case above a statement about the profile rather than about expiry.
    /// </summary>
    [Fact]
    public async Task AClientNamingNothing_KeepsTheDeploymentsExpiryTolerance()
    {
        var result = await Authenticate(
            clientProfile: null,
            expiresAt: Now.AddSeconds(-1));

        Assert.NotNull(result);
    }

    /// <summary>
    /// The forward direction reaches <c>nbf</c> as well as <c>iat</c>: FAPI 2.0 section 5.3.2.1
    /// names both, and this is the clause that answers for the first of them.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_IsHeldToItsOwnWindowOnNotBefore()
    {
        var result = await Authenticate(
            ClientSecurityProfile.Fapi2,
            notBefore: Now + BeyondEveryProfileButNone);

        Assert.Null(result);
    }

    /// <summary>
    /// And the same post-dated assertion from a client naming nothing authenticates.
    /// </summary>
    [Fact]
    public async Task AClientNamingNothing_KeepsTheDeploymentsWindowOnNotBefore()
    {
        var result = await Authenticate(
            clientProfile: null,
            notBefore: Now + BeyondEveryProfileButNone);

        Assert.NotNull(result);
    }

    /// <summary>
    /// A client naming the empty profile is not heard either way: it cannot loosen what the
    /// deployment demands, and it demands nothing of its own.
    /// </summary>
    [Fact]
    public async Task AClientNamingTheEmptyProfile_IsTreatedAsNamingNothing()
    {
        var result = await Authenticate(
            ClientSecurityProfile.None,
            issuedAt: Now + BeyondEveryProfileButNone);

        Assert.NotNull(result);
    }

    /// <summary>
    /// And an assertion inside the tighter window authenticates the FAPI client too, or the cases
    /// above would be satisfied by a pass refusing every assertion from a client naming a profile.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_KeepsAnAssertionInsideItsOwnWindow()
    {
        var result = await Authenticate(
            ClientSecurityProfile.Fapi2,
            issuedAt: Now.AddSeconds(5));

        Assert.NotNull(result);
    }

    /// <summary>
    /// The forward direction accepts an <c>nbf</c> inside the tighter window, without which the
    /// refusal above would be satisfied by a clause refusing on the mere presence of the claim.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_KeepsANotBeforeInsideItsOwnWindow()
    {
        var result = await Authenticate(
            ClientSecurityProfile.Fapi2,
            notBefore: Now.AddSeconds(5));

        Assert.NotNull(result);
    }

    private async Task<ClientInfo?> Authenticate(
        ClientSecurityProfile? clientProfile,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? notBefore = null)
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            SecurityProfile = clientProfile,
        };

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var token = CreateAssertion(issuedAt, expiresAt, notBefore);

        // The real validator drives these callbacks, and the assertion path depends on what they
        // leave behind: the issuer callback is what resolves the client into the validation context.
        tokenValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(
                async (_, parameters) =>
                {
                    if (parameters.ValidateIssuer != null)
                        await parameters.ValidateIssuer(ClientId);

                    return token;
                }));

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

        return await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });
    }

    private static JsonWebToken CreateAssertion(
        DateTimeOffset? issuedAt,
        DateTimeOffset? expiresAt,
        DateTimeOffset? notBefore)
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

        token.Payload.IssuedAt = issuedAt ?? Now;
        token.Payload.ExpiresAt = expiresAt ?? Now.AddHours(1);
        if (notBefore.HasValue)
            token.Payload.NotBefore = notBefore.Value;

        token.Payload.Audiences = [Issuer];
        return token;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
