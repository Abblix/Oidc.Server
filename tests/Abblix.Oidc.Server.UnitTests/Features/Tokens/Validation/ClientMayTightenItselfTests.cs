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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// A deployment-wide profile is a floor, so a client may ask to be held to more than the deployment
/// demands. On this path it could not be heard: the client is identified from the token being
/// validated, so its profile is unknown until the validation has finished, and the tolerance had to
/// be chosen before that.
/// </summary>
/// <remarks>
/// The answer is a second pass once the client is known. These cases are about that pass, not about
/// the first one: every token here is signed and addressed correctly, and the only thing separating
/// acceptance from refusal is which profile the client names for itself.
/// </remarks>
public class ClientMayTightenItselfTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private static readonly string Issuer = TestConstants.DefaultIssuer.ToString();

    /// <summary>
    /// A token dated a minute ahead, which no profile in this server accepts and the empty profile
    /// does: five minutes each way is what a deployment holding clients to nothing grants.
    /// </summary>
    private static readonly TimeSpan AheadOfEveryProfileButNone = TimeSpan.FromMinutes(1);

    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Runs the validator over a token the first pass accepts, with the client resolving to the
    /// profile named. The token validator is a stub: what is under test is the pass AFTER it.
    /// </summary>
    private static async Task<Result<ValidJsonWebToken, JwtValidationError>> Validate(
        ClientSecurityProfile? clientProfile,
        ClientSecurityProfile deploymentProfile,
        DateTimeOffset issuedAt)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = ClientId,
                ClientId = ClientId,
                IssuedAt = issuedAt,
                ExpiresAt = Now.AddHours(1),
                Audiences = [Issuer],
            },
        };

        var clientInfo = new ClientInfo(ClientId) { SecurityProfile = clientProfile };

        var clientInfoProvider = new Mock<IClientInfoProvider>();
        clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(clientInfo);

        var tokenValidator = new Mock<IJsonWebTokenValidator>();
        tokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(token);

        var requestInfoProvider = new Mock<IRequestInfoProvider>();
        requestInfoProvider.Setup(p => p.RequestUri).Returns(Issuer);

        var issuerProvider = new Mock<IIssuerProvider>();
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var serviceKeys = new Mock<IAuthServiceKeysProvider>();
        serviceKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<bool>()))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        var validator = new ClientJwtValidator(
            NullLogger<ClientJwtValidator>.Instance,
            requestInfoProvider.Object,
            tokenValidator.Object,
            clientInfoProvider.Object,
            new Mock<IClientKeysProvider>().Object,
            issuerProvider.Object,
            serviceKeys.Object,
            Options.Create(new OidcOptions { DefaultSecurityProfile = deploymentProfile }),
            new FixedClock(Now));

        return await validator.ValidateAsync("header.payload.signature");
    }

    /// <summary>
    /// The case this exists for: a client naming FAPI 2.0 under a deployment naming nothing is held
    /// to the ten seconds section 5.3.2.1 grants, not to the five minutes the deployment would.
    /// Before the second pass this token was accepted.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_IsHeldToItUnderADeploymentNamingNothing()
    {
        var result = await Validate(
            clientProfile: ClientSecurityProfile.Fapi2,
            deploymentProfile: ClientSecurityProfile.None,
            issuedAt: Now + AheadOfEveryProfileButNone);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("issued in the future", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And the same token from a client naming nothing is accepted, without which the case above
    /// would be satisfied by a pass that refuses every token dated ahead at all.
    /// </summary>
    [Fact]
    public async Task AClientNamingNothing_KeepsTheDeploymentsWindow()
    {
        var result = await Validate(
            clientProfile: null,
            deploymentProfile: ClientSecurityProfile.None,
            issuedAt: Now + AheadOfEveryProfileButNone);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A client naming the empty profile is not heard either way: it cannot loosen what the
    /// deployment demands, and it demands nothing of its own. The same token is accepted, which is
    /// the floor working rather than the tightening.
    /// </summary>
    [Fact]
    public async Task AClientNamingTheEmptyProfile_IsTreatedAsNamingNothing()
    {
        var result = await Validate(
            clientProfile: ClientSecurityProfile.None,
            deploymentProfile: ClientSecurityProfile.None,
            issuedAt: Now + AheadOfEveryProfileButNone);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// And a token inside the tighter window passes for the FAPI client too, or the case above would
    /// be satisfied by a pass that refuses every token from a client naming a profile.
    /// </summary>
    [Fact]
    public async Task AClientNamingFapi2_KeepsATokenInsideItsOwnWindow()
    {
        var result = await Validate(
            clientProfile: ClientSecurityProfile.Fapi2,
            deploymentProfile: ClientSecurityProfile.None,
            issuedAt: Now.AddSeconds(5));

        Assert.True(result.TryGetSuccess(out _));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
