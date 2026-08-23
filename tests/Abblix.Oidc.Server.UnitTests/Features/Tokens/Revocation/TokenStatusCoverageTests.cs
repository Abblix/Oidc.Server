// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// Every <see cref="JsonWebTokenStatus"/> is decided deliberately by the decorator rather than by falling off
/// the end of its switch.
/// </summary>
/// <remarks>
/// The switch there has no <c>default</c> arm on purpose: acceptance is the right answer for a token nothing
/// is recorded about, so a loud default would throw on every ordinary request. That leaves the usual trap -
/// a status added later inherits acceptance in silence, and a silently accepted revoked token is the failure
/// this whole component exists to prevent.
/// <para>
/// One table answers both questions below, which is the point. An earlier version kept the coverage list and
/// the drive-through cases separately, so a status added to the list and forgotten in the switch passed both
/// - the list agreed with itself and nothing drove the decorator. Here the theory enumerates the enum and
/// looks each member up in the same table the coverage test checks, so a new status fails until somebody
/// states its outcome, and stating it wrongly fails too.
/// </para>
/// <para>
/// What this still cannot catch: a status entered in the table as accepted, whose case nobody added. That is
/// a decision rather than an oversight - somebody had to write down that such a token is let through - and no
/// test can tell a wrong decision from a right one.
/// </para>
/// </remarks>
public class TokenStatusCoverageTests
{
    /// <summary>
    /// What the decorator answers for each status: an error, or <c>null</c> for a token it lets through.
    /// </summary>
    private static readonly Dictionary<JsonWebTokenStatus, JwtError?> Outcomes = new()
    {
        [JsonWebTokenStatus.Unknown] = null,
        [JsonWebTokenStatus.Used] = JwtError.TokenAlreadyUsed,
        [JsonWebTokenStatus.Revoked] = JwtError.TokenRevoked,
    };

    public static TheoryData<JsonWebTokenStatus> AllStatuses()
    {
        var data = new TheoryData<JsonWebTokenStatus>();
        foreach (var status in Enum.GetValues<JsonWebTokenStatus>())
            data.Add(status);

        return data;
    }

    [Fact]
    public void EveryStatus_HasADecidedOutcome()
    {
        var undecided = Enum.GetValues<JsonWebTokenStatus>()
            .Where(status => !Outcomes.ContainsKey(status))
            .ToArray();

        Assert.True(
            undecided.Length == 0,
            $"TokenStatusValidatorDecorator does not decide {string.Join(", ", undecided)}. Add the case to its "
            + $"switch and the outcome to {nameof(Outcomes)}, saying whether such a token is accepted or refused.");
    }

    /// <summary>
    /// And the outcome is what the table claims, driven through the decorator rather than asserted about it:
    /// a table agreeing with itself would pass over a switch that had stopped refusing anything.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllStatuses))]
    public async Task AStatus_ProducesTheOutcomeItIsListedWith(JsonWebTokenStatus status)
    {
        Assert.True(
            Outcomes.TryGetValue(status, out var expected),
            $"No outcome is listed for {status}, so this theory cannot say what the decorator owes it.");

        const string jwtId = "jti_1";

        var registry = new Mock<ITokenRegistry>(MockBehavior.Strict);
        registry.Setup(r => r.GetStatusAsync(jwtId)).ReturnsAsync(status);

        var cutoffs = new Mock<IRevocationCutoffRegistry>(MockBehavior.Strict);
        cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);

        var issuers = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuers.Setup(p => p.GetIssuer()).Returns(TestConstants.DefaultIssuer.OriginalString);

        var clients = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync(new ClientInfo("client_1") { SubjectType = SubjectTypes.Public });

        var inner = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        Result<JsonWebToken, JwtValidationError> success = new JsonWebToken
        {
            Payload =
            {
                JwtId = jwtId,
                Issuer = TestConstants.DefaultIssuer.OriginalString,
                Subject = "user_1",
                IssuedAt = new DateTimeOffset(2024, 1, 15, 11, 0, 0, TimeSpan.Zero),
                ExpiresAt = new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero),
            }
        };
        inner
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(success);

        var decorator = new TokenStatusValidatorDecorator(
            NullLogger<TokenStatusValidatorDecorator>.Instance,
            registry.Object,
            cutoffs.Object,
            issuers.Object,
            Options.Create(new OidcOptions()),
            clients.Object,
            new SubjectTypeConverter(),
            inner.Object);

        var result = await decorator.ValidateAsync("opaque.jwt", new ValidationParameters());

        if (expected is null)
        {
            Assert.True(result.TryGetSuccess(out _));
        }
        else
        {
            Assert.True(result.TryGetFailure(out var error));
            Assert.Equal(expected, error.Error);
        }
    }
}
